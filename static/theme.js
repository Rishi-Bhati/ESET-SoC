/* ESET SOC Lite — Dark / Light theme toggle
 *
 * Self-contained: only touches #themeBtnDark / #themeBtnLight and the
 * [data-theme] attribute on <html>. Does not read or modify `state`,
 * dashboard.js's rendering, or anything alert-processing related.
 *
 * Persistence: localStorage (this dashboard has no prior theme preference to
 * migrate — sessionStorage is already used for the unrelated dashboard access
 * key, see dashboard.js's `dash_key`). Using localStorage means the choice
 * survives closing the tab, not just a refresh within the same session.
 *
 * First load with no saved choice: the inline snippet in dashboard.html's
 * <head> only stamps [data-theme] when a saved value exists, so on a first
 * visit the CSS's own `@media (prefers-color-scheme: light)` block decides —
 * this file does not need to duplicate that logic, only reflect the current
 * state in the buttons.
 */
"use strict";

const THEME_STORAGE_KEY = "soc_lite_theme";

function currentTheme() {
  const explicit = document.documentElement.getAttribute("data-theme");
  if (explicit === "light" || explicit === "dark") return explicit;
  // No explicit choice yet — report whichever the CSS media query is actually
  // rendering, so the buttons open in sync with what the visitor sees.
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light" : "dark";
}

function updateThemeButtons() {
  const dark = document.getElementById("themeBtnDark");
  const light = document.getElementById("themeBtnLight");
  if (!dark || !light) return;
  const active = currentTheme();
  dark.className = "small" + (active === "dark" ? " primary" : "");
  light.className = "small" + (active === "light" ? " primary" : "");
  dark.setAttribute("aria-pressed", String(active === "dark"));
  light.setAttribute("aria-pressed", String(active === "light"));
}

function setTheme(theme) {
  if (theme !== "light" && theme !== "dark") return;
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch (e) { /* localStorage unavailable (private mode, etc.) — theme still applies for this page view */ }
  updateThemeButtons();
}

document.addEventListener("DOMContentLoaded", () => {
  const darkBtn = document.getElementById("themeBtnDark");
  const lightBtn = document.getElementById("themeBtnLight");
  if (darkBtn) darkBtn.onclick = () => setTheme("dark");
  if (lightBtn) lightBtn.onclick = () => setTheme("light");
  updateThemeButtons();

  // Keep the buttons in sync if the OS theme changes while no explicit choice
  // has been made yet (matches the CSS's own prefers-color-scheme behavior).
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
      if (!document.documentElement.getAttribute("data-theme")) updateThemeButtons();
    });
  }
});
