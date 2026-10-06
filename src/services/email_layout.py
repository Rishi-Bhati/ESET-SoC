"""
Layout for notification emails: one structured document, rendered twice.

email_composer.py decides WHAT goes into each email (which sections, from which
AI fields); this module decides how it LOOKS. Each email is described as an
EmailDocument — a heading, the risk level, an optional lead paragraph, then
titled sections that are prose, a list, label/value rows, or a quoted block —
and rendered as:

  * text — the plain-text version, kept on EmailMessage.body. It is what the
    dashboard's outbox shows and what any text-only mail client falls back to.
  * html — the version actually handed to the mail service: a single-column,
    table-based layout with inline styles only (what Outlook, Gmail and Apple
    Mail all render the same way), the risk colour as an accent, and the
    alert facts as an aligned table.

Every value that reaches the HTML is escaped here. Alert values are
attacker-controllable (a detection or file name can be anything), and AI text
is derived from them, so nothing is ever inserted as markup.
"""
from dataclasses import dataclass, field
from html import escape

# Risk accent colours (WCAG AA against white for the badge text).
_RISK_COLOR = {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#a16207", "LOW": "#15803d"}
_RISK_JA = {"CRITICAL": "緊急", "HIGH": "高", "MEDIUM": "中", "LOW": "低"}

_FONT = ("-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',"
         "'Hiragino Kaku Gothic ProN','Hiragino Sans',Meiryo,'Yu Gothic',sans-serif")
_MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"


@dataclass
class Section:
    """One titled block. Exactly one of the content fields is normally set."""
    title: str
    text: str = ""                                          # prose; blank lines separate paragraphs
    items: list[str] = field(default_factory=list)          # bulleted (or numbered) list
    numbered: bool = False
    rows: list[tuple[str, str, bool]] = field(default_factory=list)  # (label, value, monospace)
    quote: str = ""                                         # verbatim block, e.g. a draft email


@dataclass
class EmailDocument:
    lang: str            # "ja" | "en"
    heading: str
    risk_level: str
    eyebrow: str = ""    # small line above the heading: who the email is for
    lead: str = ""       # opening paragraph(s), before the first section
    sections: list[Section] = field(default_factory=list)
    footer: list[str] = field(default_factory=list)


def risk_label(level: str, lang: str) -> str:
    """'HIGH（高）' in Japanese, 'HIGH' in English."""
    return f"{level}（{_RISK_JA[level]}）" if lang == "ja" and level in _RISK_JA else level


def _clean(items: list[str]) -> list[str]:
    return [item.strip() for item in items if item and item.strip()]


# ------------------------------------------------------------------ text

def render_text(doc: EmailDocument) -> str:
    ja = doc.lang == "ja"
    rule = "━" * 28 if ja else "━" * 56
    risk_line = f"リスクレベル：{risk_label(doc.risk_level, 'ja')}" if ja else f"Risk level: {doc.risk_level}"
    out = [doc.heading, risk_line, rule]
    if doc.lead.strip():
        out += ["", doc.lead.strip()]
    for section in doc.sections:
        body = _section_text(section, ja)
        if body:
            out += ["", f"■ {section.title}", body]
    if doc.footer:
        out += ["", "─" * (28 if ja else 56), *doc.footer]
    return "\n".join(out)


def _section_text(section: Section, ja: bool) -> str:
    if section.rows:
        rows = [(label, value) for label, value, _ in section.rows if value]
        if ja:
            return "\n".join(f"・{label}：{value}" for label, value in rows)
        return "\n".join(f"- {label}: {value}" for label, value in rows)
    if section.items:
        items = _clean(section.items)
        if section.numbered:
            return "\n".join(f"{n}. {item}" for n, item in enumerate(items, 1))
        return "\n".join(f"{'・' if ja else '- '}{item}" for item in items)
    if section.quote.strip():
        lines = section.quote.strip().splitlines()
        return "\n".join(["┌" + "─" * 27, *(f"│ {line}" for line in lines), "└" + "─" * 27])
    return section.text.strip()


# ------------------------------------------------------------------ html

def render_html(doc: EmailDocument) -> str:
    color = _RISK_COLOR.get(doc.risk_level, "#374151")
    lang = "ja" if doc.lang == "ja" else "en"
    badge_text = (f"リスクレベル {risk_label(doc.risk_level, 'ja')}" if lang == "ja"
                  else f"Risk level {doc.risk_level}")

    parts = [
        f'<!DOCTYPE html><html lang="{lang}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{escape(doc.heading)}</title></head>'
        f'<body style="margin:0;padding:0;background:#f3f4f6;font-family:{_FONT};color:#1f2937">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6">'
        '<tr><td align="center" style="padding:24px 12px">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="max-width:680px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;'
        f'border-top:5px solid {color}">',
        # Header: audience, heading, risk badge
        '<tr><td style="padding:22px 28px 6px">',
    ]
    if doc.eyebrow:
        parts.append(f'<div style="font-size:12px;color:#6b7280;letter-spacing:.03em;margin-bottom:6px">'
                     f'{escape(doc.eyebrow)}</div>')
    parts.append(
        f'<div style="font-size:19px;line-height:1.45;font-weight:700;color:#111827;margin:0 0 12px">'
        f'{escape(doc.heading)}</div>'
        f'<span style="display:inline-block;background:{color};color:#ffffff;font-size:12px;font-weight:700;'
        f'padding:4px 12px;border-radius:999px">{escape(badge_text)}</span>'
        '</td></tr>'
    )
    if doc.lead.strip():
        parts.append(f'<tr><td style="padding:14px 28px 0;font-size:14px;line-height:1.75">{_prose_html(doc.lead)}</td></tr>')
    for section in doc.sections:
        body = _section_html(section)
        if not body:
            continue
        parts.append(
            '<tr><td style="padding:18px 28px 0">'
            f'<div style="font-size:14px;font-weight:700;color:#111827;border-left:4px solid {color};'
            f'padding:1px 0 1px 9px;margin:0 0 10px">{escape(section.title)}</div>'
            f'{body}</td></tr>'
        )
    if doc.footer:
        lines = "<br>".join(escape(line) for line in doc.footer)
        parts.append('<tr><td style="padding:22px 28px 22px">'
                     '<div style="border-top:1px solid #e5e7eb;padding-top:12px;font-size:12px;'
                     f'line-height:1.6;color:#6b7280">{lines}</div></td></tr>')
    else:
        parts.append('<tr><td style="padding:0 0 22px"></td></tr>')
    parts.append('</table></td></tr></table></body></html>')
    return "".join(parts)


def _section_html(section: Section) -> str:
    if section.rows:
        rows = [(label, value, mono) for label, value, mono in section.rows if value]
        if not rows:
            return ""
        cells = "".join(
            '<tr>'
            f'<td valign="top" style="padding:7px 12px 7px 0;width:32%;font-size:13px;color:#6b7280;'
            f'border-bottom:1px solid #f3f4f6">{escape(label)}</td>'
            f'<td valign="top" style="padding:7px 0;font-size:13px;color:#111827;word-break:break-all;'
            f'border-bottom:1px solid #f3f4f6;{f"font-family:{_MONO};font-size:12.5px;" if mono else ""}">{escape(value)}</td>'
            '</tr>'
            for label, value, mono in rows
        )
        return f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">{cells}</table>'
    if section.items:
        items = _clean(section.items)
        if not items:
            return ""
        tag = "ol" if section.numbered else "ul"
        lis = "".join(f'<li style="margin:0 0 6px">{escape(item)}</li>' for item in items)
        return f'<{tag} style="margin:0;padding-left:22px;font-size:14px;line-height:1.7">{lis}</{tag}>'
    if section.quote.strip():
        return ('<div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:14px 16px;'
                f'font-size:13px;line-height:1.75;white-space:pre-wrap">{escape(section.quote.strip())}</div>')
    if section.text.strip():
        return f'<div style="font-size:14px;line-height:1.75">{_prose_html(section.text)}</div>'
    return ""


def _prose_html(text: str) -> str:
    """Paragraphs on blank lines, line breaks kept; a line that is only a
    【見出し】 (as the AI writes section labels inside its Japanese prose) is
    shown in bold."""
    paragraphs = []
    for block in text.strip().split("\n\n"):
        lines = []
        for line in block.strip().splitlines():
            stripped = line.strip()
            if stripped.startswith("【") and stripped.endswith("】"):
                lines.append(f"<strong>{escape(stripped)}</strong>")
            else:
                lines.append(escape(line))
        if lines:
            paragraphs.append(f'<p style="margin:0 0 12px">{"<br>".join(lines)}</p>')
    return "".join(paragraphs)
