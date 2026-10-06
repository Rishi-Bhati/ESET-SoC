/* ESET SOC Lite — live flow graph + charts
 *
 * Loaded after dashboard.js; shares its globals (state, esc, badge, api, …).
 *
 * The pipeline flow graph below is hand-built SVG — it is a bespoke diagram, not
 * a chart, and no charting library models it. The CHARTS section further down is
 * drawn with Apache ECharts, vendored at /static/echarts.min.js so nothing is
 * fetched from a third party at page load.
 */
"use strict";

/* ══════════════════════ LIVE FLOW GRAPH ══════════════════════
 * One lane per alert. Nodes appear and connect as pipeline_stage
 * events arrive, so the lane visibly grows left-to-right.
 */

const SVG_NS = "http://www.w3.org/2000/svg";
const MAX_LANES = 7;

const FLOW = {
  padL: 20, padT: 54, laneH: 78,
  nodeW: 96, nodeH: 40, gapX: 116,
  labelH: 20,
};

/** Shortens `text` to fit `maxWidth` px at `fontSize`, appending an ellipsis.
 *
 * Widths are estimated, not measured: getComputedTextLength() would force a
 * layout per label while the flow graph is being rebuilt on every stage event.
 * Full-width CJK glyphs are approximately one em; Latin averages closer to
 * 0.55em — so the two are counted separately instead of assuming one ratio for
 * both, which is what made a single character budget wrong in one language or
 * the other whichever number was chosen.
 */
function fitText(text, maxWidth, fontSize) {
  if (!text) return "";
  const isWide = (ch) => /[\u3000-\u9fff\uff00-\uffef]/.test(ch);
  const widthOf = (str) => {
    let w = 0;
    for (const ch of str) w += (isWide(ch) ? 1 : 0.55) * fontSize;
    return w;
  };
  if (widthOf(text) <= maxWidth) return text;

  const ellipsisWidth = 0.55 * fontSize;
  let out = "";
  for (const ch of text) {
    if (widthOf(out + ch) + ellipsisWidth > maxWidth) break;
    out += ch;
  }
  return out + "…";
}

function stageColors(st) {
  switch (st) {
    // The four reached-a-stage states are drawn as small, self-contained chips
    // (fixed dark fill + matching light text, same idea as the .b-* badges in
    // dashboard.html) — they keep their own contrast regardless of page theme,
    // by design, so they stay unchanged here on purpose.
    // `sub` is the small detail line under the node label. It used to be drawn in
    // the ambient --muted, which is a DARK grey in light mode — dark grey text on
    // these fixed dark chips measured about 2:1. Each state now carries its own
    // sub colour, dimmed from its own text colour, so the pairing holds in both
    // themes.
    case "active":  return { fill: "#101c2e", stroke: "var(--accent)",   text: "#a8b6ff", sub: "#7d89b8" };
    case "ok":      return { fill: "#0d2318", stroke: "var(--good)",     text: "#5ee08f", sub: "#77a68b" };
    case "failed":  return { fill: "#2a1315", stroke: "var(--critical)", text: "#fca5a5", sub: "#b98388" };
    case "skipped": return { fill: "#2a1f0a", stroke: "var(--warning)",  text: "#fcd34d", sub: "#b89f6b" };
    // "waiting" (not yet reached) is meant to blend into the panel, not stand
    // out as a chip — so, unlike the four above, it must follow the theme.
    default:        return { fill: "var(--panel2)", stroke: "var(--border2)", text: "var(--dim)", sub: "var(--dim)" };
  }
}

function el(name, attrs, text) {
  const n = document.createElementNS(SVG_NS, name);
  for (const k in attrs) n.setAttribute(k, attrs[k]);
  if (text !== undefined) n.textContent = text;
  return n;
}

function ensureRun(correlationId, source) {
  if (!state.runs.has(correlationId)) {
    state.runs.set(correlationId, {
      correlation_id: correlationId,
      source: source || "",
      started: Date.now(),
      stages: new Map(),
    });
    // Keep only the most recent lanes
    if (state.runs.size > MAX_LANES) {
      const oldest = [...state.runs.entries()].sort((a, b) => a[1].started - b[1].started)[0];
      state.runs.delete(oldest[0]);
    }
  }
  return state.runs.get(correlationId);
}

function applyStage(d) {
  const run = ensureRun(d.correlation_id);
  run.stages.set(d.stage, { state: d.state, detail: d.detail, risk_level: d.risk_level });
  if (d.risk_level) run.risk_level = d.risk_level;
  if (state.view === "flow") renderFlow();
}

function renderFlow() {
  const svg = document.getElementById("flow");
  const runs = [...state.runs.values()].sort((a, b) => b.started - a.started);
  const width = FLOW.padL * 2 + FLOW.nodeW + FLOW.gapX * (STAGES.length - 1);
  const height = FLOW.padT + Math.max(1, runs.length) * FLOW.laneH + 16;

  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("height", height);
  svg.setAttribute("width", "100%");
  while (svg.firstChild) svg.removeChild(svg.firstChild);

  // Column headers — the pipeline stages
  STAGES.forEach((stage, i) => {
    const x = FLOW.padL + i * FLOW.gapX + FLOW.nodeW / 2;
    svg.appendChild(el("text", {
      x, y: 22, "text-anchor": "middle", fill: "var(--muted)",
      "font-size": "10.5", "font-weight": "700", "letter-spacing": ".06em",
    }, STAGE_LABEL[stage].toUpperCase()));
    svg.appendChild(el("line", {
      x1: x, y1: 30, x2: x, y2: height - 10,
      stroke: "var(--border)", "stroke-width": 1, "stroke-dasharray": "2 6",
    }));
  });

  if (!runs.length) {
    svg.appendChild(el("text", {
      x: width / 2, y: FLOW.padT + 40, "text-anchor": "middle",
      fill: "var(--muted)", "font-size": "13",
    }, t("flow_empty_svg")));
    document.getElementById("flowFoot").textContent = t("flow_foot_empty");
    return;
  }

  runs.forEach((run, laneIdx) => {
    const yTop = FLOW.padT + laneIdx * FLOW.laneH;
    const yMid = yTop + FLOW.nodeH / 2;

    // Lane header: correlation id + source + risk
    const head = el("text", {
      x: FLOW.padL, y: yTop - 8, fill: "var(--muted)", "font-size": "10.5",
      style: "font-family:var(--font-mono)",
    });
    head.textContent =
      `${run.correlation_id.slice(0, 8)}  ${run.source ? tBadgeLabel(run.source) : ""}` +
      `${run.risk_level ? "  · " + tBadgeLabel(run.risk_level) : ""}`;
    svg.appendChild(head);

    STAGES.forEach((stage, i) => {
      const x = FLOW.padL + i * FLOW.gapX;
      const info = run.stages.get(stage);
      const st = info ? info.state : "waiting";
      const c = stageColors(st);

      // Edge from the previous node
      if (i > 0) {
        const prev = run.stages.get(STAGES[i - 1]);
        const reached = !!prev;
        const edge = el("line", {
          x1: x - FLOW.gapX + FLOW.nodeW, y1: yMid, x2: x, y2: yMid,
          stroke: reached ? (info ? "var(--good)" : "var(--accent)") : "var(--border2)",
          "stroke-width": reached ? 2 : 1.25,
          "stroke-linecap": "round",
          class: "fedge" + (reached && !info ? " flowing" : ""),
        });
        svg.appendChild(edge);
      }

      // Pulse ring while a stage is running
      if (st === "active") {
        svg.appendChild(el("rect", {
          x, y: yTop, width: FLOW.nodeW, height: FLOW.nodeH, rx: 9,
          fill: "none", stroke: "var(--accent)", "stroke-width": 1.5,
          class: "fpulse", opacity: ".5",
        }));
      }

      const g = el("g", { class: "fnode", style: "cursor:pointer" });
      g.appendChild(el("rect", {
        x, y: yTop, width: FLOW.nodeW, height: FLOW.nodeH, rx: 9,
        fill: c.fill, stroke: c.stroke, "stroke-width": info ? 1.5 : 1,
      }));
      g.appendChild(el("text", {
        x: x + FLOW.nodeW / 2, y: yTop + 17, "text-anchor": "middle",
        fill: c.text, "font-size": "11", "font-weight": "700",
        // The primary label was never measured, so the longest Japanese stage
        // name (脅威インテリジェンス — 10 full-width characters ≈ 110px in a 96px
        // node) drew straight across both node borders and into its neighbour.
      }, fitText(STAGE_LABEL[stage], FLOW.nodeW - 8, 11)));

      // Second line: short state or detail. The budget is derived from the node
      // width rather than a hardcoded character count — a fixed 14 produced
      // "HIGH / severit…" and "VirusTotal 0/7…", which is a truncation so early
      // it says nothing. The full text is always on the node's <title> and in the
      // stage-detail modal, so nothing is lost by shortening it here.
      let sub = st === "waiting" ? "—" : tPipelineState(st);
      if (info && info.detail) {
        const detailJa = tStageDetail(stage, info.detail);
        sub = fitText(detailJa, FLOW.nodeW - 10, 9.5);
      }
      g.appendChild(el("text", {
        x: x + FLOW.nodeW / 2, y: yTop + 31, "text-anchor": "middle",
        fill: c.sub, "font-size": "9.5",
      }, sub));

      if (info) {
        const title = el("title");
        title.textContent = `${STAGE_LABEL[stage]} — ${tPipelineState(info.state)}${info.detail ? "\n" + tStageDetail(stage, info.detail) : ""}`;
        g.appendChild(title);
      }
      g.addEventListener("click", () => openStageDetail(run, stage));
      svg.appendChild(g);
    });
  });

  const done = runs.filter((r) => r.stages.has("OUTPUT")).length;
  document.getElementById("flowFoot").textContent = t("flow_foot", runs.length, done);
}

/** Maps a raw WS stage-event state onto one of the fixed status badge keys. */
function stageBadgeKey(state) {
  return state === "ok" ? "SUCCESS" : state === "failed" ? "FAILED" : state === "skipped" ? "PARTIAL" : "PROCESSING";
}

/** NormalizedAlert field -> i18n label key, for the NORMALIZE stage's table.
 * Reuses the labels already used elsewhere (kv_detection, kv_endpoint, …) where
 * one exists, so the same field is never worded two different ways across the
 * dashboard; the remaining fields get their own field_* label (i18n.js). */
const NORMALIZED_FIELD_LABEL_KEY = {
  source: "field_source", event_type: "field_event_type", alert_id: "field_alert_id",
  detection_uuid: "field_detection_uuid", target_uuid: "field_target_uuid",
  occurred_at: "field_occurred_at", severity: "kv_severity_reported",
  detection_name: "kv_detection", endpoint_name: "kv_endpoint",
  endpoint_type: "field_endpoint_type", user_name: "kv_user", os_name: "kv_os",
  action_taken: "kv_action_taken", threat_handled: "field_threat_handled",
  isolation_status: "field_isolation_status", object_type: "field_object_type",
  object_uri: "kv_object_uri", file_hash: "kv_file_hash", url: "field_url",
  ip_address: "field_ip_address", domain: "field_domain",
  raw_subject: "field_raw_subject", raw_content: "field_raw_content",
};
// Field order for that table: identity/what-happened first, indicators last —
// matches the order an analyst actually reads them in, not alphabetical and not
// NormalizedAlert's declaration order (which interleaves them).
const NORMALIZED_FIELD_ORDER = [
  "detection_name", "severity", "endpoint_name", "endpoint_type", "user_name", "os_name",
  "action_taken", "threat_handled", "isolation_status", "object_type", "object_uri",
  "file_hash", "url", "ip_address", "domain", "event_type", "alert_id", "occurred_at",
  "detection_uuid", "target_uuid", "source", "raw_subject", "raw_content",
];

function stageNotReached() {
  return `<p class="muted">${esc(t("stage_not_reached"))}</p>`;
}

function ingestStageBody(job) {
  if (!job) return stageNotReached();
  return `<div class="kv">
      <div>${esc(t("stage_ingest_source"))}</div><div>${badge(job.source)}</div>
      <div>${esc(t("stage_ingest_received"))}</div><div>${esc(fmtDateTime(job.created_at * 1000))}</div>
    </div>
    ${rawPayloadHtml(originalRequestPayload(job))}`;
}

function normalizeStageBody(result) {
  if (!result || !result.normalized_alert) return stageNotReached();
  const a = result.normalized_alert;
  // Only the fields the alert actually carried — an absent field is not a row.
  const rows = NORMALIZED_FIELD_ORDER.filter((field) => knownValue(a[field]) !== undefined).map((field) => {
    const labelKey = NORMALIZED_FIELD_LABEL_KEY[field] || field;
    const value = ["threat_handled", "isolation_status"].includes(field) ? tBadgeLabel(a[field]) : a[field];
    return `<div>${esc(t(labelKey))}</div><div><span class="mono">${esc(value)}</span></div>`;
  }).join("");

  return `
    <p class="muted" style="font-size:11.5px;margin:0 0 10px">${esc(t("stage_normalize_desc"))}</p>
    ${rows ? `<div class="kv">${rows}</div>` : `<p class="muted">${esc(t("stage_normalize_empty"))}</p>`}`;
}

function riskStageBody(result) {
  if (!result || !result.risk_level) return stageNotReached();
  return `
    <p class="muted" style="font-size:11.5px;margin:0 0 10px">${esc(t("stage_risk_desc"))}</p>
    <div class="kv">
      <div>${esc(t("kv_risk_computed"))}</div><div>${badge(result.risk_level)}</div>
      ${riskFactorsRow(result.risk_factors, result.risk_rationale)}
    </div>`;
}

function intelStageBody(result) {
  if (!result) return stageNotReached();
  const block = threatIntelBlock(result.threat_intel);
  return `
    <p class="muted" style="font-size:11.5px;margin:0 0 10px">${esc(t("stage_intel_desc"))}</p>
    ${block || `<p class="muted">${esc(t("stage_intel_none"))}</p>`}`;
}

function aiStageBody(result) {
  if (!result || !result.ai_output) {
    // An AI failure is recorded too (result.ai_run), so say what happened.
    const run = result && result.ai_run;
    if (!run) return `<p class="muted">${esc(t("stage_ai_not_reached"))}</p>`;
    return `
      <p style="color:var(--text-danger);font-size:12.5px;margin:0 0 10px">${esc(t("stage_ai_failed", run.error_type || run.status))}</p>
      ${aiRunKv(run)}
      ${run.error ? `<p class="muted mono" style="font-size:11.5px">${esc(run.error)}</p>` : ""}
      ${(run.validation_issues || []).length ? `<ul class="ai-list">${run.validation_issues.map((i) => `<li class="mono">${esc(i)}</li>`).join("")}</ul>` : ""}`;
  }
  return `
    <p class="muted" style="font-size:11.5px;margin:0 0 10px">${esc(t("stage_ai_desc"))}</p>
    <div class="kv">
      <div>${esc(t("stage_ai_model_risk"))}</div><div>${badge(result.ai_output.risk_level)}</div>
    </div>
    ${result.ai_run ? aiRunKv(result.ai_run) : ""}
    <button class="small" id="stageViewFullAi">${esc(t("btn_view_full_analysis"))}</button>`;
}

function lintStageBody(job, info) {
  if (!info) return stageNotReached();
  const failed = info.state === "failed";
  return `
    <p class="muted" style="font-size:11.5px;margin:0 0 10px">${esc(t("stage_lint_desc"))}</p>
    <div class="kv">
      <div>${esc(t("kv_state"))}</div><div>${badge(stageBadgeKey(info.state))}</div>
    </div>
    ${failed && job && job.error
        ? `<p style="color:var(--text-danger);font-size:12.5px">${esc(tBackendText(job.error))}</p>`
        : `<p class="muted">${esc(t("stage_lint_pass"))}</p>`}`;
}

function outputStageBody(correlationId, result) {
  if (!result) return stageNotReached();
  return `
    <p class="muted" style="font-size:11.5px;margin:0 0 10px">${esc(t("stage_output_desc"))}</p>
    <div class="kv">
      <div>${esc(t("stage_output_path"))}</div><div class="mono">output/alerts/${esc(correlationId)}.json</div>
      ${result.processed_at ? kvRow(t("kv_updated"), fmtDateTime(result.processed_at)) : ""}
    </div>`;
}

/** Fetches this alert's own emails. Split from the renderer below so
 * openAlertTimeline (which needs the list up front, synchronously, to build
 * every tab panel at once) and openStageDetail (which only ever needs the one
 * EMAIL/SEND tab, fetched on demand) can share one render function without
 * either double-fetching or the timeline view blocking tab-switching on a
 * network round trip. */
async function fetchDeliveries(correlationId) {
  try {
    const data = await api(`/delivery?correlation_id=${encodeURIComponent(correlationId)}&limit=50`);
    return data.deliveries || [];
  } catch (e) {
    return [];
  }
}

function emailStageBodyFromDeliveries(deliveries) {
  const rows = deliveries.map((d) => `
    <tr>
      <td>${badge(d.notification_type)}</td>
      <td>${esc((d.recipients || []).join(", "))}</td>
      <td>${badge(d.status)}</td>
    </tr>`).join("");

  return `
    <p class="muted" style="font-size:11.5px;margin:0 0 10px">${esc(t("stage_email_desc"))}</p>
    ${deliveries.length ? `
      <table><thead><tr>
        <th>${esc(t("stage_email_type"))}</th><th>${esc(t("stage_email_recipients"))}</th><th>${esc(t("stage_email_status"))}</th>
      </tr></thead><tbody>${rows}</tbody></table>`
      : `<p class="muted">${esc(t("stage_email_none"))}</p>`}`;
}

async function emailStageBody(correlationId) {
  return emailStageBodyFromDeliveries(await fetchDeliveries(correlationId));
}

async function openStageDetail(run, stage) {
  const info = run.stages.get(stage);
  const title = `${STAGE_LABEL[stage]} — ${run.correlation_id.slice(0, 8)}`;

  showModal(title, `<p class="muted">${esc(t("stage_loading"))}</p>`);

  let job = null, result = null;
  try {
    const data = await api(`/jobs/${encodeURIComponent(run.correlation_id)}`);
    job = data.job;
    result = data.result;
  } catch (e) { /* stage body functions below all handle job/result === null */ }

  const stateLine = `<div class="kv" style="margin-bottom:14px">
      <div>${esc(t("kv_correlation_id2"))}</div><div class="mono">${esc(run.correlation_id)}</div>
      <div>${esc(t("kv_stage"))}</div><div>${esc(STAGE_LABEL[stage])}</div>
      <div>${esc(t("kv_state"))}</div><div>${info ? badge(stageBadgeKey(info.state)) : `<span class="dim">${esc(t("stage_not_reached"))}</span>`}</div>
    </div>`;

  let body;
  switch (stage) {
    case "INGEST": body = ingestStageBody(job); break;
    case "NORMALIZE": body = normalizeStageBody(result); break;
    case "RISK": body = riskStageBody(result); break;
    case "INTEL": body = intelStageBody(result); break;
    case "AI": body = aiStageBody(result); break;
    case "LINT": body = lintStageBody(job, info); break;
    case "OUTPUT": body = outputStageBody(run.correlation_id, result); break;
    case "EMAIL":
    case "SEND": body = await emailStageBody(run.correlation_id); break;
    default: body = info && info.detail ? `<p class="muted">${esc(tStageDetail(stage, info.detail))}</p>` : stageNotReached();
  }

  showModal(title, `${stateLine}${body}
    <button class="small" id="openFullAlert" style="margin-top:14px">${esc(t("stage_open_alert"))}</button>`);

  const btn = document.getElementById("openFullAlert");
  if (btn) btn.onclick = () => openAlert(run.correlation_id);

  wireRawPayloadCopy(document.getElementById("modalBox"));
  state.reopenModal = () => openStageDetail(run, stage);

  const viewFullAi = document.getElementById("stageViewFullAi");
  if (viewFullAi && result) {
    viewFullAi.onclick = () => openAiModal({
      correlation_id: run.correlation_id,
      alert: result.normalized_alert,
      risk_level: result.risk_level,
      risk_rationale: result.risk_rationale,
      threat_intel: result.threat_intel,
      ai_output: result.ai_output,
    });
  }
}

/* A single alert's complete story — Ingest through Email — as a tab strip, built
 * from the exact same per-stage body functions openStageDetail() (above) uses
 * for the live Pipeline Flow view. The difference is what supplies `info` (the
 * per-stage ok/failed/not-reached signal each body function is written against):
 *
 *   - openStageDetail reads it from run.stages, populated by this session's own
 *     live WebSocket events — so it only ever has something to show for an alert
 *     that arrived while THIS page was open, and only for the stages reached so
 *     far. Reload the page and that alert's lane, and its stage history, are gone
 *     — nothing server-side ever recorded it (src/utils/events.py's emit_stage is
 *     fire-and-forget by design).
 *   - openAlertTimeline instead DERIVES a reached/not-reached signal from what is
 *     actually recorded for that alert — whether normalized_alert/risk_level/
 *     threat_intel/ai_output are present in its result file, and whether emails
 *     exist for its correlation_id — so it works for ANY alert, at ANY time,
 *     including ones from a previous session or before this feature existed.
 *
 * That derivation is deliberately only two-valued (reached / not reached), never
 * a guessed "failed at exactly this stage": job/result alone cannot distinguish
 * "this stage ran and failed" from "the pipeline never got this far", and
 * presenting a guess as if it were recorded fact would misdirect an analyst
 * reading this after an incident. Where the real error IS known (job.error), the
 * relevant stage body still shows it — see lintStageBody.
 *
 * EMAIL and SEND (two distinct live stages — queued vs. handed off) collapse
 * into one "Email" tab here: that queued/dispatched distinction only exists on
 * the live event feed, which this view deliberately does not depend on. The
 * email history (src/storage/delivery_store.py, filtered to this
 * correlation_id) already shows every email this alert produced and its current
 * handoff state — a fabricated queued-vs-sent split on top of it would claim
 * more precision than the data backs up.
 */
const TIMELINE_STAGES = ["INGEST", "NORMALIZE", "INTEL", "RISK", "AI", "LINT", "OUTPUT", "EMAIL"];

async function openAlertTimeline(id) {
  showModal(t("modal_alert_timeline"), `<p class="muted">${esc(t("modal_fetching_alert"))}</p>`);

  let job, result, deliveries;
  try {
    const [jobData, deliveryList] = await Promise.all([
      api(`/jobs/${encodeURIComponent(id)}`),
      fetchDeliveries(id),
    ]);
    job = jobData.job;
    result = jobData.result;
    deliveries = deliveryList;
  } catch (e) {
    showModal(t("modal_error"), `<p class="muted">${esc(tBackendText(e.message))}</p>`);
    return;
  }

  const reached = {
    INGEST: true,
    NORMALIZE: !!(result && result.normalized_alert),
    RISK: !!(result && result.risk_level),
    INTEL: !!(result && result.threat_intel),
    AI: !!(result && result.ai_output),
    // Lint runs strictly between AI generation and the output write, and a
    // failed lint blocks the write — so if the result file exists WITH AI
    // output, lint necessarily passed. This is inferred with confidence, not
    // guessed, unlike the "not reached" cases above.
    LINT: !!(result && result.ai_output),
    OUTPUT: !!result,
    EMAIL: deliveries.length > 0,
  };
  const infoFor = (stage) => (reached[stage] ? { state: "ok", detail: "" } : null);

  const bodyFor = {
    INGEST: () => ingestStageBody(job),
    NORMALIZE: () => normalizeStageBody(result),
    RISK: () => riskStageBody(result),
    INTEL: () => intelStageBody(result),
    AI: () => aiStageBody(result),
    LINT: () => lintStageBody(job, infoFor("LINT")),
    OUTPUT: () => outputStageBody(id, result),
    EMAIL: () => emailStageBodyFromDeliveries(deliveries),
  };

  const panels = TIMELINE_STAGES.map((stage) => ({
    id: stage,
    label: STAGE_LABEL[stage],
    html: `<div class="kv" style="margin-bottom:12px">
        <div>${esc(t("kv_state"))}</div><div>${
          reached[stage] ? badge("SUCCESS") : `<span class="dim">${esc(t("stage_not_reached"))}</span>`}</div>
      </div>${bodyFor[stage]()}`,
  }));

  const html = `
    <p class="muted" style="font-size:11.5px;margin:0 0 12px">${esc(t("timeline_intro"))}</p>
    <div class="kv" style="margin-bottom:14px">
      <div>${esc(t("kv_correlation_id2"))}</div><div class="mono">${esc(id)}</div>
      <div>${esc(t("kv_status2"))}</div><div>${badge(job.status)}</div>
    </div>
    <div class="tabs" role="tablist">${panels.map((p, i) =>
      `<button type="button" role="tab" class="tabbtn ${i === 0 ? "active" : ""}" ` +
      `id="timeline-tab-${esc(p.id)}" aria-controls="timeline-panel-${esc(p.id)}" ` +
      `tabindex="${i === 0 ? "0" : "-1"}" aria-selected="${i === 0}" data-tab="${esc(p.id)}">${esc(p.label)}</button>`).join("")}</div>
    ${panels.map((p, i) =>
      `<div role="tabpanel" tabindex="0" id="timeline-panel-${esc(p.id)}" ` +
      `aria-labelledby="timeline-tab-${esc(p.id)}" data-panel="${esc(p.id)}" style="${i === 0 ? "" : "display:none"}">${p.html}</div>`).join("")}
    <button class="small" id="openFullAlert" style="margin-top:14px">${esc(t("stage_open_alert"))}</button>`;

  showModal(t("modal_alert_timeline"), html);
  state.reopenModal = () => openAlertTimeline(id);

  const btn = document.getElementById("openFullAlert");
  if (btn) btn.onclick = () => openAlert(id);

  wireRawPayloadCopy(document.getElementById("modalBox"));

  const viewFullAi = document.getElementById("stageViewFullAi");
  if (viewFullAi && result) {
    viewFullAi.onclick = () => openAiModal({
      correlation_id: id,
      alert: result.normalized_alert,
      risk_level: result.risk_level,
      risk_rationale: result.risk_rationale,
      threat_intel: result.threat_intel,
      ai_output: result.ai_output,
    });
  }
}

document.getElementById("clearFlow").onclick = () => { state.runs.clear(); renderFlow(); };

/* ══════════════════════ CHARTS ══════════════════════
 *
 * Rendered with Apache ECharts (vendored at /static/echarts.min.js — see the
 * comment on its <script> tag for why it is not loaded from a CDN). The flow
 * graph above stays hand-built SVG: it is a bespoke pipeline diagram, not a
 * chart, and no charting library models it.
 *
 * Three things every chart here has to get right, and which the helpers below
 * handle once instead of per chart:
 *
 *  1. Theme. ECharts resolves colors when it renders, so it cannot consume
 *     `var(--risk-3)` — the tokens are read off the document and passed in as
 *     literal hex. That means a theme switch has to REDRAW, not just restyle,
 *     which is what the `soc:themechange` listener at the bottom does.
 *  2. Size. Several of these charts live in a view that is `display:none` at
 *     load, where the container measures 0×0 and ECharts renders nothing. A
 *     ResizeObserver per host catches the 0→N transition when the view is
 *     first shown, so no view-switching code has to remember to resize.
 *  3. Language. Labels come from t()/tBadgeLabel(), so every draw call is
 *     re-issued by refreshCurrentViewTranslations() on a language switch.
 */

/** Chart colors, resolved from the CSS custom properties for the active theme.
 * Read fresh on every draw — a theme switch changes every one of them. */
function chartTokens() {
  const css = getComputedStyle(document.documentElement);
  const v = (name, fallback) => (css.getPropertyValue(name) || "").trim() || fallback;
  return {
    text: v("--text", "#e9f4f5"),
    muted: v("--muted", "#93a8ac"),
    dim: v("--dim", "#586e72"),
    grid: v("--grid", "#16262b"),
    axis: v("--axis", "#233c44"),
    track: v("--track", "#182428"),
    // The chart surface: what a 2px "gap" or "ring" between marks is painted in.
    surface: v("--panel", "#0d1518"),
    panel2: v("--panel2", "#121c20"),
    border2: v("--border2", "#294048"),
    risk: [v("--risk-1", "#1a6378"), v("--risk-2", "#0e8fae"),
           v("--risk-3", "#22b8d6"), v("--risk-4", "#67e8f9")],
    cat: [v("--cat-1", "#0891b2"), v("--cat-2", "#d97706")],
    // --bar-* not --good/--warning/...: those are chip colours, which carry
    // their own tinted backing. A bar is painted directly on the panel and needs
    // a value that clears the panel in THIS theme.
    good: v("--bar-good", "#22c55e"),
    warning: v("--bar-warn", "#f59e0b"),
    serious: v("--bar-serious", "#f97316"),
    critical: v("--bar-critical", "#ef4444"),
  };
}

// host element -> { chart, redraw }. `redraw` replays the last draw call with
// its original data, which is how a theme switch re-renders without the caller
// having to hold on to the data or re-fetch it.
const CHARTS = new Map();

function chartHost(host) {
  let rec = CHARTS.get(host);
  if (rec) return rec;

  rec = { chart: null, redraw: null };
  CHARTS.set(host, rec);

  // 0×0 at init (a hidden view) renders nothing; this catches it becoming
  // visible, and every later container resize, without a view-switch hook.
  if (window.ResizeObserver) {
    new ResizeObserver(() => {
      if (rec.chart && host.clientWidth > 0) rec.chart.resize();
    }).observe(host);
  }
  return rec;
}

/** Initialises (or reuses) the ECharts instance for a host and applies `option`.
 * `redraw` is stored so a theme change can replay this exact chart. */
function applyChart(host, option, redraw) {
  const rec = chartHost(host);
  rec.redraw = redraw;

  const placeholder = host.querySelector(".chart-empty-box");
  if (placeholder) placeholder.remove();

  if (!rec.chart || rec.chart.isDisposed()) {
    rec.chart = echarts.init(host, null, { renderer: "svg" });
  }
  // notMerge: the previous option's series/axes must not leak into this one
  // (a filtered-out status row would otherwise linger).
  rec.chart.setOption(option, { notMerge: true });
  return rec.chart;
}

function emptyChart(host, msg, redraw) {
  const rec = chartHost(host);
  rec.redraw = redraw || rec.redraw;
  if (rec.chart && !rec.chart.isDisposed()) {
    rec.chart.dispose();
    rec.chart = null;
  }
  host.innerHTML = `<div class="chart-empty-box">${esc(msg)}</div>`;
}

/** Tooltip chrome shared by every chart, so a hover looks the same everywhere. */
function tooltipStyle(k) {
  return {
    backgroundColor: k.panel2,
    borderColor: k.border2,
    borderWidth: 1,
    padding: [8, 11],
    textStyle: { color: k.text, fontSize: 12, fontFamily: "inherit" },
    extraCssText: "border-radius:9px;box-shadow:0 10px 26px -12px rgba(0,0,0,.55);",
  };
}

/** The panel's headline figure: how many alerts arrived across the selected
 * window, and the busiest single hour in it. A flat line near zero — the normal
 * state for this dashboard — says nothing on its own; these two numbers do, and
 * they save the reader from summing the chart by eye. */
function updateSeriesHeadline(series) {
  const host = document.getElementById("seriesHeadline");
  if (!host) return;
  if (!series || !series.length) { host.innerHTML = ""; return; }
  const counts = series.map((d) => d.count);
  const total = counts.reduce((a, b) => a + b, 0);
  const peak = Math.max(...counts);
  host.innerHTML =
    `<span class="hero">${esc(fmtCount(total))}</span>` +
    `<span class="note">${esc(t("hero_in_window"))} · ${esc(t("hero_peak", peak))}</span>`;
}

/* ---- Alerts over time ------------------------------------------------------
 * One series, so no legend: the panel title already says what is plotted.
 * An area (not the previous column-per-hour) because the question this panel
 * answers is "is ingest steady, spiking, or stopped" — a shape question, which
 * a continuous line answers at a glance and a row of separate columns does not.
 */
function drawSeries(series) {
  const host = document.getElementById("chartSeries");
  updateSeriesHeadline(series);
  if (!series || !series.length) return emptyChart(host, t("chart_empty_window"), () => drawSeries(series));

  const k = chartTokens();
  const line = k.cat[0];
  const labels = series.map((d) => new Date(d.t));
  const values = series.map((d) => d.count);
  const max = Math.max(...values);

  host.style.height = "234px";
  applyChart(host, {
    animationDuration: 420,
    grid: { left: 8, right: 14, top: 14, bottom: 6, containLabel: true },
    tooltip: {
      trigger: "axis",
      ...tooltipStyle(k),
      // The crosshair is the point of an axis-triggered tooltip: it ties the
      // readout to a position in time rather than to whichever pixel was hit.
      axisPointer: {
        type: "line",
        lineStyle: { color: k.axis, width: 1 },
        label: { show: false },
      },
      formatter: (params) => {
        const p = params[0];
        const when = fmtDateTime(labels[p.dataIndex]);
        return `<div style="color:${k.muted};font-size:11px;margin-bottom:3px">${esc(when)}</div>` +
               `<strong>${esc(t("chart_tooltip_alerts", p.value))}</strong>`;
      },
    },
    xAxis: {
      type: "category",
      boundaryGap: false,
      data: labels.map((d) => fmtTime(d)),
      axisLine: { lineStyle: { color: k.axis, width: 1 } },
      axisTick: { show: false },
      // Let ECharts thin the labels itself rather than every-nth-bar guessing:
      // it measures, so labels never collide at any container width.
      axisLabel: { color: k.muted, fontSize: 10.5, hideOverlap: true, margin: 10 },
    },
    yAxis: {
      type: "value",
      // Counts are integers — without this a max of 2 yields ticks 0, 0.5, 1…
      minInterval: 1,
      max: max < 4 ? Math.max(1, max) : null,
      splitLine: { lineStyle: { color: k.grid, width: 1, type: "solid" } },
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: k.muted, fontSize: 10.5, margin: 10 },
    },
    series: [{
      type: "line",
      data: values,
      // Barely smoothed. These are discrete hourly counts, and a strong spline
      // invents a curve between two samples — with the mostly-zero, occasionally
      // spiky traffic this dashboard actually sees, that reads as a wave of
      // alerts that never happened.
      smooth: 0.15,
      // Show the samples themselves while there are few enough to be distinct;
      // over a 7-day window (168 points) they merge into a smear and the line
      // alone is clearer.
      showSymbol: values.length <= 48,
      // ≥8px, and it doubles as the hover hit target.
      symbolSize: 8,
      lineStyle: { color: line, width: 2, cap: "round", join: "round" },
      itemStyle: { color: line, borderColor: k.surface, borderWidth: 2 },
      // A wash, never a saturated block: ~14% at the line, fading to nothing.
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: line + "2b" },
          { offset: 1, color: line + "00" },
        ]),
      },
      emphasis: { focus: "series" },
    }],
  }, () => drawSeries(series));
}

/* ---- Horizontal bars, shared by risk / status / source / AI risk ------------
 * Horizontal because every category here has a word for a name (CRITICAL,
 * SENSITIVE_DATA_DETECTED); vertical columns would force those labels to
 * rotate or truncate.
 */
function drawBars(host, rows, opts) {
  if (!rows.length || rows.every((r) => r.value === 0)) {
    return emptyChart(host, opts.empty, () => drawBars(host, rows, opts));
  }

  const k = chartTokens();
  const labels = rows.map((r) => r.label);
  const max = Math.max(1, ...rows.map((r) => r.value));
  const valueText = rows.map((r) => fmtCount(r.value));
  const widestValue = Math.max(...valueText.map((v) => v.length));

  // Enough height for a ≤20px bar plus air, and the value labels at the tips.
  host.style.height = rows.length * 34 + 20 + "px";
  applyChart(host, {
    animationDuration: 420,
    // The right margin has to hold the value label that sits past the longest
    // bar's tip. A fixed reserve silently clipped the last digit of any wide
    // number ("44210" rendered as "4421"), so it is derived from the widest
    // label actually being drawn.
    grid: { left: 4, right: 16 + widestValue * 8, top: 8, bottom: 4, containLabel: true },
    tooltip: {
      trigger: "item",
      ...tooltipStyle(k),
      formatter: (p) => `${esc(p.name)}: <strong>${esc(fmtCount(p.value))}</strong>`,
    },
    xAxis: {
      type: "value",
      max: max,
      show: false,
      // No x-axis: every bar is directly labelled with its own value, so an
      // axis would only repeat what the labels already say.
    },
    yAxis: {
      type: "category",
      data: labels,
      inverse: true,
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: k.muted, fontSize: 11.5, fontWeight: 600, margin: 12 },
    },
    series: [{
      type: "bar",
      data: rows.map((r, i) => ({
        value: r.value,
        itemStyle: {
          // barMinHeight (below) guarantees a visible bar for any non-zero value,
          // but it applies to zero too — which would draw a coloured stub for a
          // count of 0 and make "no failures" look like "a few failures". A zero
          // row keeps its label and its axis entry, and draws nothing.
          color: r.value > 0 ? r.color : "transparent",
          // 4px rounded data-end, square where it meets the baseline.
          borderRadius: [0, 4, 4, 0],
        },
        label: { show: true, formatter: valueText[i] },
      })),
      barMaxWidth: 20,
      barCategoryGap: "38%",
      // A non-zero value must never draw as nothing: CRITICAL=2 against a max of
      // 44210 rounded to zero pixels, so the row looked identical to CRITICAL=0.
      // On a SOC dashboard that is the single worst thing a bar chart can do.
      barMinHeight: 3,
      // No track behind the bar. It was decoration rather than data — these bars
      // are a comparison between categories, not a set of meters against a
      // capacity — and it cost twice over: mid-tone fills only reached ~2:1
      // against a near-white track in light mode, and a zero-value label ended up
      // parked *inside* the track while every other label sat outside its bar, so
      // one chart carried three different label placements. Painted straight on
      // the panel, the fills use their validated contrast and every label sits in
      // the same place.
      showBackground: false,
      label: {
        show: true,
        position: "right",
        distance: 9,
        // Text wears a text token, never the series colour.
        color: k.text,
        fontSize: 11.5,
        fontWeight: 700,
      },
      emphasis: { itemStyle: { opacity: 0.86 } },
    }],
  }, () => drawBars(host, rows, opts));
}

function drawRisk(byRisk) {
  // Ordinal severity -> single-hue ramp (validated); the risk badge beside each
  // row in the tables carries the red/amber status vocabulary.
  const k = chartTokens();
  const order = [["LOW", k.risk[0]], ["MEDIUM", k.risk[1]], ["HIGH", k.risk[2]], ["CRITICAL", k.risk[3]]];
  drawBars(document.getElementById("chartRisk"),
    order.map(([key, color]) => ({ label: tBadgeLabel(key), value: (byRisk || {})[key] || 0, color })),
    { empty: t("chart_empty_completed") });
}

function drawStatus(byStatus) {
  // Status palette: these bars encode STATE (succeeded / degraded / failed), the
  // one job status color is reserved for. Every bar is directly labelled with
  // its name and its count, so color is never the only channel.
  const k = chartTokens();
  const order = [
    ["SUCCESS", k.good], ["PARTIAL", k.warning],
    ["FAILED", k.critical], ["PROCESSING", k.cat[0]], ["PENDING", k.dim],
  ];
  drawBars(document.getElementById("chartStatus"),
    order.map(([key, color]) => ({ label: tBadgeLabel(key), value: (byStatus || {})[key] || 0, color, _key: key }))
         .filter((r) => r.value > 0 || ["SUCCESS", "PARTIAL", "FAILED"].includes(r._key)),
    { empty: t("chart_empty_alerts") });
}

/* ---- AI Visibility risk breakdown — same pattern as drawRisk() ---- */
function drawAiRisk(byRisk) {
  const k = chartTokens();
  // Seven categories, and four of them used to share one identical red — four
  // bars a reader could not tell apart without reading every label. They are not
  // the same thing: a leaked secret, a blocked generation, a failed safety check
  // and a provider error need different responses. They keep the same severity
  // family (all four are bad) but step within it, so the ordering still reads
  // while the categories stay distinguishable. The ramp is the ordinal risk ramp,
  // matching the Overview's Risk Distribution chart rather than inventing a
  // second colour system for a second risk chart.
  const order = [
    ["SAFE", k.good], ["REVIEW", k.warning],
    ["SENSITIVE_DATA_DETECTED", k.serious],
    ["SECRET_DETECTED", k.critical],
    ["FAILED_SECURITY_CHECK", k.risk[3]],
    ["BLOCKED", k.risk[2]],
    ["ERROR", k.dim],
  ];
  const rows = order
    .map(([key, color]) => ({ label: tBadgeLabel(key), value: (byRisk || {})[key] || 0, color, _key: key }))
    .filter((r) => r.value > 0 || ["SAFE", "REVIEW"].includes(r._key));
  drawBars(document.getElementById("aiRiskChart"), rows, { empty: t("chart_empty_ai_traces") });
}

function drawSource(bySource) {
  // Identity, not magnitude: the two ingest paths get the two categorical
  // slots in fixed order, so WEBHOOK stays cyan whether or not SYSLOG has data.
  const k = chartTokens();
  const order = [["WEBHOOK", k.cat[0]], ["SYSLOG", k.cat[1]]];
  const rows = order.map(([key, color]) => ({ label: tBadgeLabel(key), value: (bySource || {})[key] || 0, color }));
  const extra = Object.keys(bySource || {}).filter((key) => !["WEBHOOK", "SYSLOG"].includes(key));
  // Anything beyond the two known sources folds into the de-emphasis gray
  // rather than being handed a generated hue.
  for (const key of extra) rows.push({ label: tBadgeLabel(key), value: bySource[key], color: k.dim });
  drawBars(document.getElementById("chartSource"), rows, { empty: t("chart_empty_alerts") });
}

/* Theme switches change every token a chart was drawn with, and ECharts holds
 * the resolved hex values, so each live chart is replayed with the new ones. */
document.addEventListener("soc:themechange", () => {
  for (const rec of CHARTS.values()) {
    if (rec.redraw) rec.redraw();
  }
});

window.addEventListener("resize", () => {
  for (const rec of CHARTS.values()) {
    if (rec.chart && !rec.chart.isDisposed()) rec.chart.resize();
  }
});
