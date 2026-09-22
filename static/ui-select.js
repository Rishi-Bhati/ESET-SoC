/* Custom dropdown for every <select> on the dashboard.
 *
 * The native popup was unreliable here: on some browser/OS combinations it
 * closed on mouse-up, so an option could only be chosen by pressing, dragging
 * and releasing on it. It also ignores the theme. This replaces the visible
 * control with a button + listbox while keeping the real <select> in the DOM
 * as the single source of truth: picking an option sets select.value and
 * dispatches a normal "change" event, so every existing `select.onchange`
 * handler and `select.value` read keeps working unchanged.
 *
 * The button label follows the select through a MutationObserver, so option
 * text re-translated by applyStaticI18n(), or options rebuilt by script, show
 * up without the callers knowing this component exists. Call
 * enhanceSelect(el) for a <select> created after page load.
 */
"use strict";

(function () {
  let open = null; // { sel, btn, menu, active }

  function optionsOf(sel) {
    return [...sel.options].filter((o) => !o.hidden);
  }

  function syncLabel(sel, btn) {
    const o = sel.options[sel.selectedIndex];
    btn.querySelector(".uisel-label").textContent = o ? o.textContent : "";
    const label = sel.getAttribute("aria-label") || sel.getAttribute("title");
    if (label) btn.setAttribute("aria-label", `${label}: ${o ? o.textContent : ""}`);
    btn.disabled = sel.disabled;
  }

  function close(refocus) {
    if (!open) return;
    const { btn, menu } = open;
    menu.remove();
    btn.setAttribute("aria-expanded", "false");
    open = null;
    if (refocus) btn.focus();
  }

  function setActive(i) {
    const items = open.menu.querySelectorAll(".uisel-opt");
    if (!items.length) return;
    open.active = Math.max(0, Math.min(i, items.length - 1));
    items.forEach((el, n) => el.classList.toggle("active", n === open.active));
    const el = items[open.active];
    open.menu.setAttribute("aria-activedescendant", el.id);
    el.scrollIntoView({ block: "nearest" });
  }

  function choose(i) {
    const { sel, menu } = open;
    const el = menu.querySelectorAll(".uisel-opt")[i];
    close(true);
    // By value, not index: the options may have been rebuilt while open.
    if (!el || el.classList.contains("disabled") || sel.value === el.dataset.value) return;
    if (![...sel.options].some((o) => o.value === el.dataset.value)) return;
    sel.value = el.dataset.value;
    sel.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function place(btn, menu) {
    const r = btn.getBoundingClientRect();
    menu.style.minWidth = r.width + "px";
    const below = window.innerHeight - r.bottom;
    const h = Math.min(menu.scrollHeight, 320);
    menu.style.left = Math.min(r.left, window.innerWidth - menu.offsetWidth - 8) + "px";
    menu.style.top = (below < h + 12 && r.top > below ? r.top - h - 4 : r.bottom + 4) + "px";
  }

  let uid = 0;
  function show(sel, btn) {
    close(false);
    const menu = document.createElement("div");
    menu.className = "uisel-menu";
    menu.setAttribute("role", "listbox");
    menu.tabIndex = -1;
    const opts = optionsOf(sel);
    menu.innerHTML = "";
    opts.forEach((o, i) => {
      const el = document.createElement("div");
      el.className = "uisel-opt" + (o.selected ? " selected" : "") + (o.disabled ? " disabled" : "");
      el.id = `uisel-${++uid}`;
      el.setAttribute("role", "option");
      el.setAttribute("aria-selected", String(o.selected));
      el.textContent = o.textContent;
      el.dataset.index = i;
      el.dataset.value = o.value;
      menu.appendChild(el);
    });
    document.body.appendChild(menu);
    place(btn, menu);
    btn.setAttribute("aria-expanded", "true");
    open = { sel, btn, menu, active: 0 };
    setActive(Math.max(0, opts.findIndex((o) => o.selected)));
    menu.focus({ preventScroll: true });

    // A plain click (not press-and-hold) picks the option.
    menu.addEventListener("click", (e) => {
      const el = e.target.closest(".uisel-opt");
      if (el && !el.classList.contains("disabled")) choose(Number(el.dataset.index));
    });
    menu.addEventListener("mousemove", (e) => {
      const el = e.target.closest(".uisel-opt");
      if (el && Number(el.dataset.index) !== open.active) setActive(Number(el.dataset.index));
    });
    menu.addEventListener("keydown", (e) => {
      const n = opts.length;
      if (e.key === "ArrowDown") { e.preventDefault(); setActive(open.active + 1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); setActive(open.active - 1); }
      else if (e.key === "Home") { e.preventDefault(); setActive(0); }
      else if (e.key === "End") { e.preventDefault(); setActive(n - 1); }
      else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); choose(open.active); }
      else if (e.key === "Escape") { e.preventDefault(); close(true); }
      else if (e.key === "Tab") { close(false); }
      else if (e.key.length === 1) {
        const k = e.key.toLowerCase();
        const start = open.active + 1;
        for (let j = 0; j < n; j++) {
          const idx = (start + j) % n;
          if (opts[idx].textContent.trim().toLowerCase().startsWith(k)) { setActive(idx); break; }
        }
      }
    });
  }

  function enhanceSelect(sel) {
    if (!sel || sel.dataset.uisel) return;
    sel.dataset.uisel = "1";
    const wrap = document.createElement("span");
    wrap.className = "uisel";
    sel.parentNode.insertBefore(wrap, sel);
    wrap.appendChild(sel);
    sel.classList.add("uisel-native");
    sel.tabIndex = -1;
    sel.setAttribute("aria-hidden", "true");

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "uisel-btn";
    if (sel.id) btn.id = sel.id + "Btn";
    btn.setAttribute("aria-haspopup", "listbox");
    btn.setAttribute("aria-expanded", "false");
    btn.innerHTML = '<span class="uisel-label"></span>';
    wrap.appendChild(btn);
    syncLabel(sel, btn);

    btn.addEventListener("click", () => {
      if (open && open.sel === sel) close(true); else show(sel, btn);
    });
    btn.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); show(sel, btn); }
    });
    sel.addEventListener("change", () => syncLabel(sel, btn));
    new MutationObserver(() => syncLabel(sel, btn)).observe(sel, {
      childList: true, subtree: true, characterData: true, attributes: true,
    });
  }

  document.addEventListener("mousedown", (e) => {
    if (open && !open.menu.contains(e.target) && !open.btn.contains(e.target)) close(false);
  }, true);
  // The menu is position:fixed against the button's rect; rather than chase
  // the button, close on any scroll or resize outside the menu itself.
  document.addEventListener("scroll", (e) => {
    if (open && e.target !== open.menu) close(false);
  }, true);
  window.addEventListener("resize", () => close(false));

  window.enhanceSelect = enhanceSelect;
  document.querySelectorAll("select").forEach(enhanceSelect);
})();
