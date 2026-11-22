"""
The language choice for engineer recommendations in the browser, run with Node.js
on the real code: recommendationBody() in static/dashboard.js (engineering
dashboard) and recommendationText() in static/client/client.js (client portal),
with the real translation dictionaries. Skipped when Node.js is not installed.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js not installed")


def _function(path: str, name: str) -> str:
    """Source of a top-level `function name(...) {...}` (ends at the first line that is just '}')."""
    src = (ROOT / path).read_text(encoding="utf-8")
    m = re.search(rf"^function {name}\(.*?^\}}$", src, re.MULTILINE | re.DOTALL)
    assert m, f"{name} not found in {path}"
    return m.group(0)


def _run(script: str) -> dict:
    out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, encoding="utf-8",
                         cwd=ROOT, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


STUBS = """
const fs = require("fs"), vm = require("vm");
const ctx = vm.createContext({
  localStorage: { getItem: () => null, setItem() {} },
  document: { documentElement: {}, addEventListener() {}, querySelectorAll: () => [], getElementById: () => null },
  navigator: { language: "en" }, window: { addEventListener() {} },
});
"""

TRANSLATED = {"body": "Isolate the host", "body_ja": "端末を隔離してください", "body_ja_status": "done"}
PENDING = {"body": "Isolate the host", "body_ja": None, "body_ja_status": None}
FAILED = {"body": "Isolate the host", "body_ja": None, "body_ja_status": "failed"}


def test_dashboard_shows_the_translation_in_japanese_and_the_original_in_english():
    fn = _function("static/dashboard.js", "recommendationBody")
    script = STUBS + f"""
vm.runInContext(fs.readFileSync("static/i18n.js", "utf8"), ctx);
vm.runInContext({json.dumps(fn)}, ctx);
const recs = {json.dumps([TRANSLATED, PENDING, FAILED])};
const out = {{}};
for (const lang of ["en", "ja", "en", "ja"]) {{             // switching back and forth
  vm.runInContext(`state_lang.current = "${{lang}}"`, ctx);
  out[lang] = recs.map((r) => ctx.recommendationBody(r));
}}
process.stdout.write(JSON.stringify(out));
"""
    out = _run(script)
    assert out["en"] == [{"text": "Isolate the host", "note": ""}] * 3
    translated, pending, failed = out["ja"]
    assert translated == {"text": "端末を隔離してください", "note": ""}
    assert pending["text"] == "Isolate the host" and "原文" in pending["note"]
    assert failed["text"] == "Isolate the host" and "作成できません" in failed["note"]


def test_dashboard_item_renders_the_chosen_text_once():
    item = _function("static/dashboard.js", "recommendationItemHtml")
    assert "esc(shown.text)" in item and "esc(rec.body)" not in item


def test_portal_shows_the_translation_in_japanese_and_the_original_in_english():
    fn = _function("static/client/client.js", "recommendationText")
    script = STUBS + f"""
vm.runInContext(fs.readFileSync("static/client/client-i18n.js", "utf8"), ctx);
vm.runInContext("var state = {{ lang: 'en' }}; function t(k) {{ return CLIENT_I18N[state.lang][k]; }}", ctx);
vm.runInContext({json.dumps(fn)}, ctx);
const recs = {json.dumps([{"body": TRANSLATED["body"], "body_ja": TRANSLATED["body_ja"]},
                          {"body": PENDING["body"], "body_ja": None}])};
const out = {{}};
for (const lang of ["ja", "en", "ja"]) {{
  vm.runInContext(`state.lang = "${{lang}}"`, ctx);
  out[lang] = recs.map((r) => ctx.recommendationText(r));
}}
process.stdout.write(JSON.stringify(out));
"""
    out = _run(script)
    assert out["en"] == [{"text": "Isolate the host", "note": ""}] * 2
    assert out["ja"][0] == {"text": "端末を隔離してください", "note": ""}
    assert out["ja"][1]["text"] == "Isolate the host" and "日本語訳" in out["ja"][1]["note"]


def test_portal_detail_uses_the_helper():
    src = (ROOT / "static/client/client.js").read_text(encoding="utf-8")
    assert "const shown = recommendationText(r);" in src and "esc(r.body)" not in src


def test_new_strings_exist_in_both_languages():
    script = STUBS + """
vm.runInContext(fs.readFileSync("static/i18n.js", "utf8"), ctx);
vm.runInContext(fs.readFileSync("static/client/client-i18n.js", "utf8"), ctx);
const pick = (o, keys) => Object.fromEntries(keys.map((k) => [k, o[k] || null]));
const d = ["rec_translation_pending", "rec_translation_unavailable"];
process.stdout.write(JSON.stringify({
  dash: { ja: pick(ctx.I18N ? ctx.I18N.ja : vm.runInContext("I18N.ja", ctx), d),
          en: pick(vm.runInContext("I18N.en", ctx), d) },
  client: { ja: pick(vm.runInContext("CLIENT_I18N.ja", ctx), ["rec_untranslated"]),
            en: pick(vm.runInContext("CLIENT_I18N.en", ctx), ["rec_untranslated"]) },
}));
"""
    out = _run(script)
    for table in (out["dash"]["ja"], out["dash"]["en"], out["client"]["ja"], out["client"]["en"]):
        assert all(table.values()), table
