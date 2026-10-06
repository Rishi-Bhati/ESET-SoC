"""
Dashboard translation guards (static/i18n.js and the markup/scripts around it).

  * Japanese text uses hiragana, katakana and Japanese kanji only — any ideograph
    outside the Japanese character set (CP932) is a Chinese-only form.
  * The ja and en tables carry exactly the same keys, so switching language can
    never fall back to English (or to a bare key) for a missing entry.
  * Every visible text node in dashboard.html is either translated
    (data-i18n) or deliberately literal (brand, numbers, symbols, technical
    identifiers in .mono).
"""
import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[2] / "static"
_IDEOGRAPH_RE = re.compile(r"[㐀-䶿一-鿿豈-﫿\U00020000-\U0003ffff]")


@pytest.mark.parametrize("name", ["i18n.js", "dashboard.js", "dashboard-viz.js", "dashboard.html"])
def test_no_chinese_only_characters(name):
    bad = set()
    for char in _IDEOGRAPH_RE.findall((STATIC / name).read_text(encoding="utf-8")):
        try:
            char.encode("cp932")
        except UnicodeEncodeError:
            bad.add(char)
    assert not bad, f"{name} contains non-Japanese ideographs: {''.join(sorted(bad))}"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_ja_and_en_tables_have_the_same_keys():
    script = (
        "global.localStorage={getItem(){return null},setItem(){}};"
        "global.document={addEventListener(){},documentElement:{}};"
        f"eval(require('fs').readFileSync({json.dumps(str(STATIC / 'i18n.js'))},'utf8')"
        "+';console.log(JSON.stringify({ja:Object.keys(I18N.ja),en:Object.keys(I18N.en)}))');"
    )
    keys = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout)
    assert sorted(set(keys["en"]) - set(keys["ja"])) == []
    assert sorted(set(keys["ja"]) - set(keys["en"])) == []


# Text that is the same in every language: the product name, the logo mark,
# numbers, arrows/pager glyphs, the language button labels themselves, and
# protocol names.
_LITERAL_OK = re.compile(r"^(ESET SOC Lite|SL|日本語|EN|AI|UDP|TCP|[\d\s]+|[‹›«»…—]+)$")


class _UntranslatedText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack: list[tuple[str, dict]] = []
        self.found: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in {"br", "input", "img", "meta", "link", "hr", "path", "circle", "rect", "line"}:
            return
        self.stack.append((tag, dict(attrs)))

    def handle_endtag(self, tag):
        while self.stack and self.stack.pop()[0] != tag:
            pass

    def handle_data(self, data):
        text = data.strip()
        if not text or not self.stack or any(t in {"script", "style", "title"} for t, _ in self.stack):
            return
        tag, attrs = self.stack[-1]
        if "data-i18n" in attrs or "mono" in attrs.get("class", "").split():
            return
        # Rewritten by JS on every render/language switch (see dashboard.js).
        if attrs.get("id") in {"wsLabel", "cAlerts", "cAiAlerts", "cEmails", "alertsEmpty"}:
            return
        if not _LITERAL_OK.match(text):
            self.found.append(text)


def test_every_visible_html_text_is_translated():
    html = (STATIC / "dashboard.html").read_text(encoding="utf-8")
    parser = _UntranslatedText()
    parser.feed(html[html.index("<body"):])
    assert parser.found == []
