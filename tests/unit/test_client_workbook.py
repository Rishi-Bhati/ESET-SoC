"""
The client workbook (src/services/client_workbook.py): allowlisted columns in
the requested order, text-only cells, and nothing internal in the file.
"""
import io
import zipfile

import pytest
from openpyxl import load_workbook

from src.config import settings
from src.services.alert_catalog import AlertBundle
from src.services.client_fields import REGISTRY, WEEKLY_FIELDS
from src.services.client_workbook import SHEET_NAMES, build_workbook
from src.services.xlsx_writer import EXCEL_CELL_MAX
from test_client_fields import CREATED_AT, sentinel_bundle

ALL_KEYS = list(REGISTRY)


def _bundle(cid="cid-1", **alert) -> AlertBundle:
    return AlertBundle(
        job={"correlation_id": cid, "created_at": CREATED_AT, "raw_payload": {"raw_payload": {"id": cid}}},
        result={"correlation_id": cid, "risk_level": "HIGH",
                "normalized_alert": {"detection_name": "Win32/Test", "endpoint_name": "HOST-1", **alert},
                "ai_output": {"alert_summary_ja": "概要です。", "risk_reason_ja": "理由です。"}},
        recommendations=[],
    )


def _xml(content: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        return "".join(z.read(n).decode("utf-8", "replace") for n in z.namelist())


def _sheet_xml(content: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        return b"".join(z.read(n) for n in z.namelist() if n.startswith("xl/worksheets/"))


async def _load(bundles, keys, lang="en", info=False, title="Alerts export"):
    content = await build_workbook(bundles, keys, lang, info, title)
    assert content[:2] == b"PK"
    return content, load_workbook(io.BytesIO(content))


# ------------------------------------------------------------- validation

class _Untouchable:
    def __iter__(self):
        raise AssertionError("bundles must not be read before the field keys are validated")


@pytest.mark.parametrize("keys", [["alert_id", "internal_summary_ja"], ["ai_run.request_id"],
                                  ["risk_factors"], [], ["alert_id", "alert_id"], "alert_id"])
async def test_bad_field_selections_are_rejected_before_any_work(keys):
    with pytest.raises(ValueError):
        await build_workbook(_Untouchable(), keys, "en", True, "x")


@pytest.mark.parametrize("lang", ["fr", "JA", "", None])
async def test_header_language_is_validated(lang):
    with pytest.raises(ValueError):
        await build_workbook(_Untouchable(), ["alert_id"], lang, False, "x")


# --------------------------------------------------------------- layout

@pytest.mark.parametrize("lang", ["ja", "en"])
async def test_headers_follow_the_language_and_columns_the_requested_order(lang):
    keys = ["risk_level", "alert_id", "engineer_recommendations", "detection_name"]
    _, wb = await _load([_bundle("cid-1"), _bundle("cid-2")], keys, lang)
    ws = wb[SHEET_NAMES[lang]["alerts"]]
    label = "label_ja" if lang == "ja" else "label_en"
    assert [c.value for c in ws[1]] == [getattr(REGISTRY[k], label) for k in keys]
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    assert len(rows) == 2
    assert rows[0][:2] == ("HIGH", "cid-1") and rows[1][1] == "cid-2"
    assert rows[0][3] == "Win32/Test"
    assert wb.sheetnames == [SHEET_NAMES[lang]["alerts"]], "no info sheet unless asked"


async def test_all_cells_are_text():
    _, wb = await _load([_bundle()], ALL_KEYS)
    for row in wb.active.iter_rows(min_row=2):
        for cell in row:
            assert cell.value is None or cell.data_type == "s", cell.coordinate


async def test_an_empty_selection_of_alerts_still_gives_a_valid_workbook():
    _, wb = await _load([], WEEKLY_FIELDS, "ja", info=True)
    assert [c.value for c in wb.active[1]] == [REGISTRY[k].label_ja for k in WEEKLY_FIELDS]
    assert wb.active.max_row == 1


async def test_info_sheet_describes_the_export_without_server_details():
    content, wb = await _load([_bundle("a"), _bundle("b"), _bundle("c")], ["alert_id", "risk_level"],
                              "en", info=True, title="Weekly report 2026-11-02")
    assert wb.sheetnames == ["Alerts", "Export info"]
    info = {k: v for k, v in wb["Export info"].iter_rows(min_row=2, values_only=True)}
    assert info["Title"] == "Weekly report 2026-11-02"
    assert info["Alerts"] == "3"
    assert info["Fields"] == "Alert ID\nRisk level"
    assert len(info["Generated at (JST)"]) == 19
    xml = _xml(content)
    for internal in (settings.output_dir, "output/alerts", "/home/", "/srv/", "soc_lite.db"):
        assert internal not in xml

    _, wb_ja = await _load([_bundle()], ["alert_id"], "ja", info=True, title="週次レポート")
    assert wb_ja.sheetnames == ["アラート", "エクスポート情報"]
    assert dict(wb_ja["エクスポート情報"].iter_rows(min_row=2, values_only=True))["タイトル"] == "週次レポート"


# ------------------------------------------------------------- security

@pytest.mark.parametrize("payload", [
    '=HYPERLINK("http://evil.example","click")', "+cmd|' /C calc'!A0", "-2+3+cmd|' /C calc'!A0",
    "@SUM(1+1)*cmd|' /C calc'!A0", "=1+1",
])
async def test_formula_injection_strings_stay_text(payload):
    bundle = _bundle(detection_name=payload, endpoint_name=payload)
    bundle.recommendations.append({"id": "r1", "body": payload, "author": payload, "created_at": CREATED_AT,
                                   "retracted_at": None})
    content, wb = await _load([bundle], ["detection_name", "endpoint_name", "engineer_recommendations"],
                              info=True, title=payload)
    cells = wb.active[2]
    assert cells[0].value == payload and cells[0].data_type == "s"
    assert cells[1].value == payload and cells[1].data_type == "s"
    assert cells[2].data_type == "s"
    assert b"<f>" not in _sheet_xml(content), "no cell may be written as a formula"
    for row in wb["Export info"].iter_rows():
        for cell in row:
            assert cell.value is None or cell.data_type == "s"


async def test_oversized_values_are_truncated_at_the_excel_cell_limit():
    huge = "A" * (EXCEL_CELL_MAX + 1000)
    _, wb = await _load([_bundle(raw_content=huge)], ["alert_id", "raw_content"], info=True)
    value = wb.active["B2"].value
    assert len(value) == EXCEL_CELL_MAX and "truncated" in value
    info = {k: v for k, v in wb["Export info"].iter_rows(min_row=2, values_only=True)}
    assert info["Cells truncated at Excel's 32,767-character limit"] == "1"


async def test_a_workbook_with_every_field_leaks_nothing_internal():
    bundle, expected, forbidden = sentinel_bundle()
    content, wb = await _load([bundle], ALL_KEYS, "en", info=True, title="Everything")
    xml = _xml(content)
    leaked = [s for s in forbidden if s in xml]
    assert not leaked, f"internal data in the workbook: {leaked}"
    assert "SECRET_" not in xml and "/srv/" not in xml
    row = dict(zip(ALL_KEYS, next(wb.active.iter_rows(min_row=2, values_only=True))))
    for key, value in expected.items():
        assert row[key] == value, key


async def test_retracted_recommendations_never_reach_the_client_workbook():
    bundle, _, _ = sentinel_bundle()
    content, wb = await _load([bundle], ["engineer_recommendations"])
    assert "SECRET_RETRACTED" not in _xml(content)
    assert wb.active["A2"].value.count("\n") == 1


async def test_a_partial_alert_where_the_ai_failed_is_exported():
    partial = AlertBundle(
        job={"correlation_id": "cid-p", "created_at": CREATED_AT, "raw_payload": {}},
        result={"correlation_id": "cid-p", "risk_level": "LOW", "pipeline_status": "PARTIAL",
                "normalized_alert": {}, "ai_output": None, "ai_run": {"status": "FAILED"}},
        recommendations=[],
    )
    _, wb = await _load([_bundle(), partial], WEEKLY_FIELDS, "ja")
    rows = list(wb.active.iter_rows(min_row=2, values_only=True))
    assert len(rows) == 2
    partial_row = dict(zip(WEEKLY_FIELDS, rows[1]))
    assert partial_row["alert_id"] == "cid-p" and partial_row["risk_level"] == "LOW"
    assert partial_row["ai_alert_summary_ja"] in (None, "")
