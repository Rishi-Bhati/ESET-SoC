"""
Shared .xlsx plumbing for every spreadsheet the platform produces: the
engineering "Convert to Spreadsheet" export (src/services/alert_export.py) and
the client-facing workbooks (src/services/client_workbook.py).

Alert content is attacker-influenced, so SheetWriter stores every string as
text — never as a formula, whatever it starts with — strips characters Excel
cannot store, and caps each cell at Excel's per-cell limit.
"""
import json
from datetime import datetime, timezone
from typing import Any, Sequence

from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Font
from openpyxl.utils import get_column_letter

from src.utils.jst_time import CONVERTED, JST, parse_alert_time

EXCEL_CELL_MAX = 32_767
DATETIME_FORMAT = "yyyy-mm-dd hh:mm:ss"


# ------------------------------------------------------------------ times

def epoch_jst(value: Any) -> datetime | None:
    """Epoch seconds as a naive JST date-time (None if not a usable number)."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).astimezone(JST).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None


def iso_jst(value: Any) -> datetime | str | None:
    """A timestamp string as a JST date-time, or the string as given if its zone is unknown."""
    if value in (None, ""):
        return None
    parsed = parse_alert_time(value)
    return parsed.jst.replace(tzinfo=None) if parsed.status == CONVERTED else parsed.en


def jst_text(value: datetime | None, seconds: bool = True) -> str:
    """A naive JST date-time as 'YYYY-MM-DD HH:MM[:SS]' ('' for None)."""
    if value is None:
        return ""
    return value.strftime("%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M")


def recommendation_line(rec: dict[str, Any]) -> str:
    """One engineer recommendation as '[YYYY-MM-DD HH:MM JST] author: body'."""
    when = jst_text(epoch_jst(rec.get("created_at")), seconds=False)
    stamp = f"[{when} JST] " if when else ""
    return f"{stamp}{rec.get('author') or ''}: {rec.get('body') or ''}"


def recommendations_text(recs: Sequence[dict[str, Any]] | None, active_only: bool = True) -> str:
    """Recommendations one per line, oldest first (newest last). Retracted ones
    are skipped unless active_only is False."""
    chosen = [r for r in (recs or []) if isinstance(r, dict)
              and not (active_only and r.get("retracted_at") is not None)]
    chosen.sort(key=lambda r: (r.get("created_at") if isinstance(r.get("created_at"), (int, float)) else 0,
                               str(r.get("id") or "")))
    return "\n".join(recommendation_line(r) for r in chosen)


# ---------------------------------------------------------------- writing

class SheetWriter:
    """Writes header + rows to a worksheet; counts cells it had to truncate."""

    def __init__(self) -> None:
        self.truncated_cells = 0

    def cell_value(self, value: Any) -> Any:
        if value is None or isinstance(value, (bool, int, float, datetime)):
            return value
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
        text = ILLEGAL_CHARACTERS_RE.sub("�", text)
        if len(text) > EXCEL_CELL_MAX:
            self.truncated_cells += 1
            note = f"… [truncated: Excel cell limit, {len(text)} characters in full]"
            text = text[:EXCEL_CELL_MAX - len(note)] + note
        return text

    def _put(self, ws, row: int, column: int, value: Any):
        value = self.cell_value(value)
        cell = ws.cell(row=row, column=column, value=value)
        if isinstance(value, str):
            cell.data_type = "s"           # text, never a formula
            if "\n" in value:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
        elif isinstance(value, datetime):
            cell.number_format = DATETIME_FORMAT
        return cell

    def write(self, ws, columns: Sequence[str], rows: Sequence[dict[str, Any]],
              headers: Sequence[str] | None = None) -> None:
        """`columns` are the row-dict keys, in order; `headers` (default: the
        keys themselves) is the text shown in row 1."""
        headers = list(columns if headers is None else headers)
        if len(headers) != len(columns):
            raise ValueError("headers and columns must have the same length")
        for c, header in enumerate(headers, start=1):
            self._put(ws, 1, c, header).font = Font(bold=True)
        for r, row in enumerate(rows, start=2):
            for c, column in enumerate(columns, start=1):
                self._put(ws, r, c, row.get(column))
        ws.freeze_panes = "B2"
        if rows:
            ws.auto_filter.ref = ws.dimensions
        for c, header in enumerate(headers, start=1):
            ws.column_dimensions[get_column_letter(c)].width = min(max(len(str(header)) + 2, 14), 60)
