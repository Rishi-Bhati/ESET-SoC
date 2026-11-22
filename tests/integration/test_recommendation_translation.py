"""
Japanese translations of engineer recommendations (services/recommendation_translation.py):
identifier protection, the provider call, storage beside the untouched original,
the background catch-up, and every place the Japanese text must appear (dashboard
API, client portal, dashboard export, client export, weekly report).
"""
import io
import json
import time

import openpyxl
import pytest
from fastapi.testclient import TestClient

from ai_fakes import FakeProvider
from client_auth_helpers import ENGINEER, enable_portal, make_client_session, session_header
from src.config import settings
from src.services import recommendation_translation as rt
from src.services import weekly_report
from src.services.ai import factory as ai_factory
from src.services.ai.base import AIConfigurationError, ProviderResponse
from src.services.xlsx_writer import UNTRANSLATED_PREFIX, recommendation_body
from src.storage import ai_trace_store, recommendation_store
from test_client_api import seed

NOW = time.time()
CID = "trans-alert-1"
REC = ("Isolate FINANCE-PC-09 from the network and run a full scan.\n"
       "- Block 185.220.101.5 and https://bad.example/payload.exe on the firewall\n"
       "- Run `Get-Process -Name evil` and check C:\\Users\\alice\\AppData\\evil.exe\n"
       "- Hash: a4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5")

# What a model would return: Japanese, every placeholder kept, line layout kept.
JA_LINES = {
    "Isolate FINANCE-PC-09 from the network and run a full scan.":
        "FINANCE-PC-09 をネットワークから隔離し、フルスキャンを実行してください。",
    "- Block [[P1]] and [[P2]] on the firewall":
        "- ファイアウォールで [[P1]] および [[P2]] をブロックしてください",
    "- Run [[P3]] and check [[P4]]": "- [[P3]] を実行し、[[P4]] を確認してください",
    "- Hash: [[P5]]": "- ハッシュ値: [[P5]]",
}


def translate_like_a_model(text: str) -> str:
    return "\n".join(JA_LINES.get(line, f"（訳）{line}") for line in text.split("\n"))


def responder_for(translate):
    def respond(request):
        assert request.schema_name == "recommendation_translation", request.schema_name
        texts = json.loads(request.user_prompt)["texts"]
        return ProviderResponse(text=json.dumps({"translations": [translate(t) for t in texts]},
                                                ensure_ascii=False),
                                request_id="req-tr", served_model="mock-model")
    return respond


@pytest.fixture
def translation_on(monkeypatch, ai_responder):
    monkeypatch.setattr(settings, "recommendation_translation_enabled", True)
    ai_responder(responder_for(translate_like_a_model))


@pytest.fixture
async def alert():
    await seed(CID, NOW - 600, risk="MEDIUM")


@pytest.fixture
def auth(client: TestClient, monkeypatch) -> dict[str, str]:
    enable_portal(monkeypatch)
    return session_header(make_client_session(client))


def _add(client, body, author="eng.a"):
    r = client.post(f"/dashboard/api/alerts/{CID}/recommendations", headers=ENGINEER,
                    json={"body": body, "author": author})
    assert r.status_code == 201, r.text
    return r.json()["recommendation"]


def _recs(client):
    return client.get(f"/dashboard/api/alerts/{CID}/recommendations", headers=ENGINEER).json()["recommendations"]


EXPECTED_JA = ("FINANCE-PC-09 をネットワークから隔離し、フルスキャンを実行してください。\n"
               "- ファイアウォールで 185.220.101.5 および https://bad.example/payload.exe をブロックしてください\n"
               "- `Get-Process -Name evil` を実行し、C:\\Users\\alice\\AppData\\evil.exe を確認してください\n"
               "- ハッシュ値: a4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5")


# ------------------------------------------------------------------ protection

def test_identifiers_are_replaced_and_restored_exactly():
    masked, tokens = rt.protect(REC)
    assert tokens == ["185.220.101.5", "https://bad.example/payload.exe", "`Get-Process -Name evil`",
                      "C:\\Users\\alice\\AppData\\evil.exe",
                      "a4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5"]
    for t in tokens:
        assert t not in masked
    assert rt.restore(masked, tokens) == REC


@pytest.mark.parametrize("text,expected", [
    ("Mail admin@corp.example about it.", ["admin@corp.example"]),
    ("Disable CORP\\jsmith now.", ["CORP\\jsmith"]),
    ("Check HKLM\\Software\\Microsoft\\Windows\\Run.", ["HKLM\\Software\\Microsoft\\Windows\\Run"]),
    ("Remove /etc/cron.d/evil and /tmp/x.sh.", ["/etc/cron.d/evil", "/tmp/x.sh"]),
    ("Block 10.0.0.0/8 and 192.168.1.5:4444, then fe80::1ff:fe23:4567:890a.",
     ["10.0.0.0/8", "192.168.1.5:4444", "fe80::1ff:fe23:4567:890a"]),
    ("Visit hxxp://evil[.]example/x (defanged).", ["hxxp://evil[.]example/x"]),
    ("Reset passwords and/or rotate keys.", []),
])
def test_identifier_patterns(text, expected):
    masked, tokens = rt.protect(text)
    assert tokens == expected
    assert rt.restore(masked, tokens) == text


@pytest.mark.parametrize("bad", ["only [[P1]]", "[[P1]] [[P1]] [[P2]]", "[[P1]] [[P2]] [[P3]]", "[[P 1]] [[P2]]"])
def test_restore_rejects_changed_placeholders(bad):
    with pytest.raises(ValueError):
        rt.restore(bad, ["a", "b"])


@pytest.mark.parametrize("text,ja", [
    ("端末をネットワークから隔離してください。", True),
    ("185.220.101.5 をブロックし、ESET PROTECT でフルスキャンを実行してください。", True),
    ("Isolate the host and run a full scan.", False),
    ("隔离主机并运行全盘扫描。", False),           # Chinese: kanji, no kana
    ("", False),
])
def test_looks_japanese(text, ja):
    assert rt.looks_japanese(text) is ja


def test_recommendation_body_language_choice():
    rec = {"body": "Isolate the host", "body_ja": "端末を隔離してください", "body_ja_status": "done"}
    assert recommendation_body(rec) == "Isolate the host"
    assert recommendation_body(rec, ja=True) == "端末を隔離してください"
    pending = {"body": "Isolate the host", "body_ja": None, "body_ja_status": None}
    assert recommendation_body(pending, ja=True) == UNTRANSLATED_PREFIX + "Isolate the host"
    failed = {"body": "Isolate the host", "body_ja": "stale", "body_ja_status": "failed"}
    assert recommendation_body(failed, ja=True) == UNTRANSLATED_PREFIX + "Isolate the host"


# ------------------------------------------------------------------ end to end

async def test_new_recommendation_is_translated_and_original_kept(client, alert, translation_on):
    created = _add(client, REC)
    assert created["body"] == REC

    [rec] = _recs(client)                     # the background task ran after the response
    assert rec["body"] == REC                 # original untouched
    assert rec["body_ja_status"] == "done"
    assert rec["body_ja"] == EXPECTED_JA      # identifiers byte-for-byte, layout kept

    # Identifiers never left the platform: the provider saw placeholders only.
    [request] = [r for r in FakeProvider.requests if r.schema_name == "recommendation_translation"]
    sent = json.loads(request.user_prompt)["texts"][0]
    for secret in ("185.220.101.5", "bad.example", "alice", "Get-Process", "a4f5b6c7"):
        assert secret not in sent
    assert "マルウェア" in request.system_prompt and "[[P1]]" in request.system_prompt

    # The call is audited like every other AI call (AI Visibility), under its alert.
    traces = await ai_trace_store.list_traces(component="recommendations.translate")
    assert [(t["correlation_id"], t["status"]) for t in traces] == [(CID, "SUCCESS")]


async def test_portal_and_exports_carry_the_japanese_text(client, alert, auth, translation_on):
    _add(client, REC)

    # Client portal: body_ja next to the original; the page picks by language.
    detail = client.get(f"/client/api/alerts/{CID}", headers=auth).json()
    [rec] = detail["recommendations"]
    assert rec["body"] == REC and rec["body_ja"] == EXPECTED_JA

    # Dashboard export: original column unchanged, Japanese column beside it,
    # both on the Recommendations sheet too.
    r = client.get("/dashboard/api/alerts/export", headers=ENGINEER)
    wb = openpyxl.load_workbook(io.BytesIO(r.content))
    ws = wb["Alerts"] if "Alerts" in wb.sheetnames else wb.active
    header = [c.value for c in ws[1]]
    row = dict(zip(header, [c.value for c in ws[2]]))
    assert row["engineer_recommendations"].endswith(REC)
    assert row["engineer_recommendations_ja"].endswith(EXPECTED_JA)
    assert header.index("engineer_recommendations_ja") == header.index("engineer_recommendations") + 1
    assert ws.cell(row=2, column=header.index("engineer_recommendations_ja") + 1).alignment.wrap_text
    rec_ws = wb["Recommendations"]
    rec_header = [c.value for c in rec_ws[1]]
    rec_row = dict(zip(rec_header, [c.value for c in rec_ws[2]]))
    assert rec_row["body"] == REC and rec_row["body_ja"] == EXPECTED_JA

    # Client export (portal download) and the weekly report: Japanese, as their other content.
    r = client.post("/client/api/alerts/export", headers=auth,
                    json={"fields": ["alert_id", "engineer_recommendations"], "header_lang": "en"})
    assert r.status_code == 200, r.text
    cells = [c for row in openpyxl.load_workbook(io.BytesIO(r.content)).active.iter_rows(values_only=True)
             for c in row if isinstance(c, str)]
    assert any(c.endswith(EXPECTED_JA) for c in cells) and not any(REC in c for c in cells)

    content = await weekly_report.build_content(weekly_report.current_period(), always_build_file=True)
    cells = [c for row in openpyxl.load_workbook(io.BytesIO(content.xlsx)).active.iter_rows(values_only=True)
             for c in row if isinstance(c, str)]
    assert any(EXPECTED_JA in c for c in cells) and not any(REC in c for c in cells)


async def test_existing_and_multiple_recommendations_are_caught_up(client, alert, translation_on):
    # Recommendations that existed before translation was switched on.
    first = await recommendation_store.create(CID, "Isolate the host.", "eng.a")
    second = await recommendation_store.create(CID, "Reset the user's password.", "eng.b")
    japanese = await recommendation_store.create(CID, "端末を隔離してください。", "eng.c")
    calls_before = len(FakeProvider.requests)

    counts = await rt.translate_pending()
    assert counts == {"translated": 2, "already_japanese": 1, "failed": 0, "unavailable": 0}
    # One call for both English recommendations of the alert; none for the Japanese one.
    assert len(FakeProvider.requests) - calls_before == 1
    by_id = {r["id"]: r for r in _recs(client)}
    assert by_id[first["id"]]["body_ja"] == "（訳）Isolate the host."
    assert by_id[second["id"]]["body_ja"] == "（訳）Reset the user's password."
    assert by_id[japanese["id"]]["body_ja"] == "端末を隔離してください。"
    assert all(r["body_ja_status"] == "done" for r in by_id.values())

    # Nothing left to do: a second pass makes no call.
    assert await rt.translate_pending() == {"translated": 0, "already_japanese": 0, "failed": 0, "unavailable": 0}
    assert len(FakeProvider.requests) - calls_before == 1


async def test_a_retracted_and_readded_recommendation_gets_its_own_translation(client, alert, translation_on):
    old = _add(client, "Isolate the host.")
    client.post(f"/dashboard/api/recommendations/{old['id']}/retract", headers=ENGINEER,
                json={"retracted_by": "eng.a", "reason": "wrong host"})
    new = _add(client, "Isolate FINANCE-PC-09 from the network and run a full scan.")
    by_id = {r["id"]: r for r in _recs(client)}
    assert by_id[old["id"]]["body_ja"] == "（訳）Isolate the host."
    assert by_id[new["id"]]["body_ja"] == "FINANCE-PC-09 をネットワークから隔離し、フルスキャンを実行してください。"


async def test_a_lost_placeholder_is_rejected_and_retried(client, alert, translation_on, ai_responder):
    ai_responder(responder_for(lambda t: "ブロックしてください"))     # drops every placeholder
    _add(client, "Block 185.220.101.5 on the firewall")
    [rec] = _recs(client)
    assert rec["body_ja_status"] == "failed" and rec["body_ja"] is None
    assert rec["body"] == "Block 185.220.101.5 on the firewall"

    ai_responder(responder_for(lambda t: t.replace("Block", "").replace("on the firewall", "")
                               .strip() + " をファイアウォールでブロックしてください"))
    await rt.translate_pending()
    [rec] = _recs(client)
    assert rec["body_ja_status"] == "done"
    assert rec["body_ja"] == "185.220.101.5 をファイアウォールでブロックしてください"


async def test_provider_errors_are_retried_then_given_up(client, alert, translation_on, ai_responder):
    ai_responder(lambda request: RuntimeError("provider down"))
    _add(client, "Isolate the host.")                 # attempt 1 (background task)
    for _ in range(rt.MAX_ATTEMPTS + 2):
        await rt.translate_pending()
    [rec] = _recs(client)
    assert rec["body_ja_status"] == "failed"
    calls = [r for r in FakeProvider.requests if r.schema_name == "recommendation_translation"]
    # A RuntimeError is not retried inside the provider, so one call per attempt,
    # and no more passes are made after MAX_ATTEMPTS.
    assert len(calls) == rt.MAX_ATTEMPTS
    assert await recommendation_store.needing_translation(10, rt.MAX_ATTEMPTS) == []


async def test_without_an_ai_provider_it_waits_and_catches_up_later(client, alert, translation_on, monkeypatch):
    def unavailable():
        raise AIConfigurationError("no key")
    monkeypatch.setattr(ai_factory, "get_ai_provider", unavailable)
    _add(client, "Isolate the host.")
    for _ in range(rt.MAX_ATTEMPTS + 2):              # never counted as attempts
        assert (await rt.translate_pending())["unavailable"] in (0, 1)
    [rec] = _recs(client)
    assert rec["body_ja_status"] == "unavailable"

    monkeypatch.setattr(ai_factory, "get_ai_provider", lambda: FakeProvider())
    await rt.translate_pending()
    [rec] = _recs(client)
    assert rec["body_ja_status"] == "done" and rec["body_ja"] == "（訳）Isolate the host."


async def test_disabled_translation_changes_nothing(client, alert, monkeypatch):
    monkeypatch.setattr(settings, "recommendation_translation_enabled", False)
    _add(client, "Isolate the host.")
    [rec] = _recs(client)
    assert rec["body_ja"] is None and rec["body_ja_status"] is None
    assert not [r for r in FakeProvider.requests if r.schema_name == "recommendation_translation"]


async def test_a_new_translation_is_pushed_to_open_dashboards(client, alert, translation_on, monkeypatch):
    from src.utils import events
    seen = []
    original = events.emit

    async def capture(type_, data):
        seen.append((type_, data))
        return await original(type_, data)
    monkeypatch.setattr(rt.events, "emit", capture)
    rec = _add(client, "Isolate the host.")
    assert ("recommendation_translated", {"correlation_id": CID, "ids": [rec["id"]]}) in seen
