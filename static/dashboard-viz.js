/* ESET SOC Lite — live flow graph + charts
 *
 * Loaded after dashboard.js; shares its globals (state, esc, badge, api, …).
 * All SVG is built by hand — no chart library, so nothing external is fetched.
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

function stageColors(st) {
  switch (st) {
    case "active":  return { fill: "#123048", stroke: "var(--accent)",   text: "#9ec5f4" };
    case "ok":      return { fill: "#0f2a16", stroke: "var(--good)",     text: "#5fd66a" };
    case "failed":  return { fill: "#331213", stroke: "var(--critical)", text: "#f08a8a" };
    case "skipped": return { fill: "#31280a", stroke: "var(--warning)",  text: "#f3c86a" };
    default:        return { fill: "#171f28", stroke: "#2e3a47",         text: "#5b6672" };
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
    }, "Waiting for alerts — send one to /webhook/eset and it will appear here live."));
    document.getElementById("flowFoot").textContent =
      "Each incoming alert becomes a lane and advances through the pipeline in real time.";
    return;
  }

  runs.forEach((run, laneIdx) => {
    const yTop = FLOW.padT + laneIdx * FLOW.laneH;
    const yMid = yTop + FLOW.nodeH / 2;

    // Lane header: correlation id + source + risk
    const head = el("text", {
      x: FLOW.padL, y: yTop - 8, fill: "var(--muted)", "font-size": "10.5",
      "font-family": "ui-monospace,SFMono-Regular,Menlo,monospace",
    });
    head.textContent =
      `${run.correlation_id.slice(0, 8)}  ${run.source || ""}${run.risk_level ? "  · " + run.risk_level : ""}`;
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
          stroke: reached ? (info ? "var(--good)" : "var(--accent)") : "#2e3a47",
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
      }, STAGE_LABEL[stage]));

      // Second line: short state or detail
      let sub = st === "waiting" ? "—" : st;
      if (info && info.detail) {
        sub = info.detail.length > 15 ? info.detail.slice(0, 14) + "…" : info.detail;
      }
      g.appendChild(el("text", {
        x: x + FLOW.nodeW / 2, y: yTop + 31, "text-anchor": "middle",
        fill: "var(--muted)", "font-size": "9.5",
      }, sub));

      if (info) {
        const title = el("title");
        title.textContent = `${STAGE_LABEL[stage]} — ${info.state}${info.detail ? "\n" + info.detail : ""}`;
        g.appendChild(title);
      }
      g.addEventListener("click", () => openStageDetail(run, stage));
      svg.appendChild(g);
    });
  });

  const done = runs.filter((r) => r.stages.has("OUTPUT")).length;
  document.getElementById("flowFoot").textContent =
    `${runs.length} recent run${runs.length === 1 ? "" : "s"} · ${done} reached output. Click a node for stage detail.`;
}

function openStageDetail(run, stage) {
  const info = run.stages.get(stage);
  const rows = STAGES.map((s) => {
    const i = run.stages.get(s);
    return `<div>${esc(STAGE_LABEL[s])}</div><div>${
      i ? `${badge(i.state === "ok" ? "SUCCESS" : i.state === "failed" ? "FAILED" : i.state === "skipped" ? "PARTIAL" : "PROCESSING")} <span class="muted">${esc(i.detail || "")}</span>`
        : '<span class="dim">not reached</span>'}</div>`;
  }).join("");

  showModal(`${STAGE_LABEL[stage]} — ${run.correlation_id.slice(0, 8)}`, `
    <div class="kv">
      <div>Correlation ID</div><div class="mono">${esc(run.correlation_id)}</div>
      <div>Stage</div><div>${esc(STAGE_LABEL[stage])}</div>
      <div>State</div><div>${info ? esc(info.state) : '<span class="dim">not reached</span>'}</div>
      ${info && info.detail ? `<div>Detail</div><div>${esc(info.detail)}</div>` : ""}
    </div>
    <h4 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">Full run</h4>
    <div class="kv">${rows}</div>
    <button class="small" id="openFullAlert">Open full alert detail</button>`);

  const btn = document.getElementById("openFullAlert");
  if (btn) btn.onclick = () => openAlert(run.correlation_id);
}

document.getElementById("clearFlow").onclick = () => { state.runs.clear(); renderFlow(); };

/* ══════════════════════ CHARTS ══════════════════════ */

function svgRoot(host, w, h) {
  const s = el("svg", { class: "chart", viewBox: `0 0 ${w} ${h}`, width: "100%", height: h });
  host.innerHTML = "";
  host.appendChild(s);
  return s;
}

function emptyChart(host, msg) {
  const s = svgRoot(host, 400, 150);
  s.appendChild(el("text", {
    x: 200, y: 78, "text-anchor": "middle", class: "chart-empty",
  }, msg));
}

/* ---- Alerts over time: single series, so no legend needed ---- */
function drawSeries(series) {
  const host = document.getElementById("chartSeries");
  if (!series || !series.length) return emptyChart(host, "No alerts in this window yet");

  const W = 560, H = 210, mL = 34, mR = 12, mT = 14, mB = 30;
  const iw = W - mL - mR, ih = H - mT - mB;
  const max = Math.max(1, ...series.map((d) => d.count));
  const s = svgRoot(host, W, H);

  // Y gridlines + ticks. Counts are integers, so never emit a repeated tick
  // label (max=2 with a fixed 4 steps would render 0,1,1,2,2).
  const steps = Math.max(1, Math.min(4, max));
  for (let i = 0; i <= steps; i++) {
    const v = Math.round((max / steps) * i);
    const y = mT + ih - (ih * i) / steps;
    s.appendChild(el("line", { x1: mL, y1: y, x2: mL + iw, y2: y, class: "tick-line" }));
    s.appendChild(el("text", { x: mL - 7, y: y + 3.5, "text-anchor": "end", class: "axis-label" }, String(v)));
  }

  const bw = Math.max(2, (iw / series.length) * 0.62);
  series.forEach((d, i) => {
    const x = mL + (iw / series.length) * (i + 0.5);
    const h = (d.count / max) * ih;
    if (d.count > 0) {
      // 4px rounded data-end, anchored to the baseline
      s.appendChild(el("rect", {
        x: x - bw / 2, y: mT + ih - h, width: bw, height: h,
        rx: Math.min(4, bw / 2), fill: "var(--risk-3)",
      }));
    }
    // Hour label every few bars so they never collide
    const every = Math.ceil(series.length / 8);
    if (i % every === 0) {
      s.appendChild(el("text", {
        x, y: H - 9, "text-anchor": "middle", class: "axis-label",
      }, new Date(d.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })));
    }
    const t = el("title");
    t.textContent = `${new Date(d.t).toLocaleString()} — ${d.count} alert(s)`;
    s.appendChild(t);
    // Invisible wide hit target for hover
    const hit = el("rect", { x: x - iw / series.length / 2, y: mT, width: iw / series.length, height: ih, fill: "transparent" });
    const ht = el("title");
    ht.textContent = `${new Date(d.t).toLocaleString()} — ${d.count} alert(s)`;
    hit.appendChild(ht);
    s.appendChild(hit);
  });

  s.appendChild(el("line", { x1: mL, y1: mT + ih, x2: mL + iw, y2: mT + ih, class: "axis-line" }));
}

/* ---- Horizontal bars, shared by risk / status / source ---- */
function drawBars(host, rows, opts) {
  if (!rows.length || rows.every((r) => r.value === 0)) return emptyChart(host, opts.empty);

  const rowH = 34, W = 560, mL = 92, mR = 46;
  const H = rows.length * rowH + 16;
  const iw = W - mL - mR;
  const max = Math.max(1, ...rows.map((r) => r.value));
  const s = svgRoot(host, W, H);

  rows.forEach((r, i) => {
    const y = 8 + i * rowH;
    const bh = 17;
    s.appendChild(el("text", {
      x: mL - 10, y: y + bh / 2 + 4, "text-anchor": "end", class: "axis-label",
    }, r.label));

    // Track
    s.appendChild(el("rect", { x: mL, y, width: iw, height: bh, rx: 4, fill: "#1a222c" }));
    const w = Math.max(r.value > 0 ? 3 : 0, (r.value / max) * iw);
    if (w > 0) {
      s.appendChild(el("rect", { x: mL, y, width: w, height: bh, rx: 4, fill: r.color }));
    }
    // Direct value label — identity never rests on colour alone
    s.appendChild(el("text", { x: mL + w + 9, y: y + bh / 2 + 4, class: "bar-val" }, String(r.value)));

    const t = el("title");
    t.textContent = `${r.label}: ${r.value}`;
    s.appendChild(t);
  });
}

function drawRisk(byRisk) {
  // Ordinal severity -> single-hue blue ramp (validated); labels carry identity
  const order = [
    ["LOW", "var(--risk-1)"], ["MEDIUM", "var(--risk-2)"],
    ["HIGH", "var(--risk-3)"], ["CRITICAL", "var(--risk-4)"],
  ];
  drawBars(document.getElementById("chartRisk"),
    order.map(([k, color]) => ({ label: k, value: (byRisk || {})[k] || 0, color })),
    { empty: "No completed alerts yet" });
}

function drawStatus(byStatus) {
  // Status palette — each bar is directly labelled, so colour is never the only cue
  const order = [
    ["SUCCESS", "var(--good)"], ["PARTIAL", "var(--warning)"],
    ["FAILED", "var(--critical)"], ["PROCESSING", "var(--accent)"], ["PENDING", "var(--dim)"],
  ];
  drawBars(document.getElementById("chartStatus"),
    order.map(([k, color]) => ({ label: k, value: (byStatus || {})[k] || 0, color }))
         .filter((r) => r.value > 0 || ["SUCCESS", "PARTIAL", "FAILED"].includes(r.label)),
    { empty: "No alerts yet" });
}

function drawSource(bySource) {
  const order = [["WEBHOOK", "var(--cat-1)"], ["SYSLOG", "var(--cat-2)"]];
  const rows = order.map(([k, color]) => ({ label: k, value: (bySource || {})[k] || 0, color }));
  const extra = Object.keys(bySource || {}).filter((k) => !["WEBHOOK", "SYSLOG"].includes(k));
  for (const k of extra) rows.push({ label: k, value: bySource[k], color: "var(--dim)" });
  drawBars(document.getElementById("chartSource"), rows, { empty: "No alerts yet" });
}
