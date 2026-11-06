"""
Builds the .xlsx workbook handed to clients (portal export and weekly report).

Only fields from the client_fields allowlist can appear, in exactly the order
requested. Alert text is attacker-influenced: every cell is written through
xlsx_writer.SheetWriter as text — never a formula, whatever it starts with —
and capped at Excel's cell limit. Nothing about the server (paths, hosts,
internal ids beyond the alert's own) is written.
"""
import asyncio
import io
from datetime import datetime
from typing import Any, Sequence

from openpyxl import Workbook

from src.services.alert_catalog import AlertBundle
from src.services.client_fields import FieldSpec, get_fields
from src.services.xlsx_writer import SheetWriter, jst_text
from src.utils.jst_time import JST

HEADER_LANGS = ("ja", "en")

# Sheet names per header language.
SHEET_NAMES: dict[str, dict[str, str]] = {
    "ja": {"alerts": "アラート", "info": "エクスポート情報"},
    "en": {"alerts": "Alerts", "info": "Export info"},
}

_INFO_LABELS: dict[str, dict[str, str]] = {
    "ja": {
        "title": "タイトル", "generated_at": "作成日時 (JST)", "rows": "アラート件数",
        "fields": "出力項目", "truncated": "Excel のセル上限 (32,767 文字) で切り詰めたセル数",
        "times": "日時", "times_note": "日時はすべて日本標準時 (JST, UTC+09:00) です",
        "item": "項目", "value": "値",
    },
    "en": {
        "title": "Title", "generated_at": "Generated at (JST)", "rows": "Alerts",
        "fields": "Fields", "truncated": "Cells truncated at Excel's 32,767-character limit",
        "times": "Times", "times_note": "All times are Japan Standard Time (JST, UTC+09:00)",
        "item": "Item", "value": "Value",
    },
}


def _validate(field_keys: Sequence[str], header_lang: str) -> list[FieldSpec]:
    if header_lang not in HEADER_LANGS:
        raise ValueError(f"header_lang must be one of {', '.join(HEADER_LANGS)}")
    if isinstance(field_keys, str):
        raise ValueError("field_keys must be a list of field keys")
    keys = list(field_keys)
    if not keys:
        raise ValueError("At least one field must be selected")
    if len(set(keys)) != len(keys):
        raise ValueError("Each field may be selected only once")
    return get_fields(keys)              # ValueError naming any unknown key


def _as_text(value: Any) -> str:
    """Every client cell is text: numbers/bools included, None as ''."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value if isinstance(value, str) else str(value)


def _build(bundles: list[AlertBundle], specs: list[FieldSpec], header_lang: str,
           include_info_sheet: bool, title: str) -> bytes:
    columns = [s.key for s in specs]
    headers = [s.label_ja if header_lang == "ja" else s.label_en for s in specs]
    rows = [{s.key: _as_text(s.extractor(b)) for s in specs} for b in bundles]

    writer = SheetWriter()
    wb = Workbook()
    ws = wb.active
    ws.title = SHEET_NAMES[header_lang]["alerts"]
    writer.write(ws, columns, rows, headers=headers)

    if include_info_sheet:
        labels = _INFO_LABELS[header_lang]
        info = wb.create_sheet(SHEET_NAMES[header_lang]["info"])
        generated = jst_text(datetime.now(JST).replace(tzinfo=None, microsecond=0))
        info_rows = [
            {"k": labels["title"], "v": _as_text(title)},
            {"k": labels["generated_at"], "v": generated},
            {"k": labels["rows"], "v": str(len(rows))},
            {"k": labels["fields"], "v": "\n".join(headers)},
            {"k": labels["times"], "v": labels["times_note"]},
        ]
        # Counted after the data sheet is written, so it is final.
        info_rows.append({"k": labels["truncated"], "v": str(writer.truncated_cells)})
        writer.write(info, ["k", "v"], info_rows, headers=[labels["item"], labels["value"]])
        info.column_dimensions["A"].width = 48
        info.column_dimensions["B"].width = 60

    wb.properties.title = _as_text(title)[:255] or None
    wb.properties.creator = "ESET SOC Lite"
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


async def build_workbook(
    bundles: Sequence[AlertBundle],
    field_keys: Sequence[str],
    header_lang: str,
    include_info_sheet: bool,
    title: str,
) -> bytes:
    """
    One row per bundle, one column per field in `field_keys` (validated through
    client_fields.get_fields -> ValueError if unknown). header_lang is "ja" or "en".
    include_info_sheet adds a sheet describing the export (title, generated-at in JST,
    row count). Returns the .xlsx file bytes; CPU work runs off the event loop.
    """
    specs = _validate(field_keys, header_lang)        # before any work
    return await asyncio.to_thread(_build, list(bundles), specs, header_lang,
                                   bool(include_info_sheet), title)
