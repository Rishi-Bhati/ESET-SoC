"""
Japanese wording for the rule engine's risk factors (src/services/risk_engine.py).

The rule engine writes each factor's `detail` in English: it is the audit
record, and the English engineer email quotes it verbatim. The Japanese
emails need the same sentence in Japanese, so this module maps every sentence
the engine can currently produce onto its Japanese version — exact strings
first, then the templated ones that carry a value (a provider name, an
endpoint, a count). The dashboard has the same table in static/i18n.js for
the UI. A sentence that matches nothing is returned unchanged, so a future
wording change shows the English rather than a wrong translation;
tests/unit/test_risk_text_ja.py fails when that happens.
"""
import re

_RISK_JA = {"CRITICAL": "CRITICAL（緊急）", "HIGH": "HIGH（高）", "MEDIUM": "MEDIUM（中）", "LOW": "LOW（低）"}

_EXACT = {
    "Alert severity is CRITICAL. Immediate escalation required regardless of mitigation status.":
        "アラートの重大度は CRITICAL（緊急）です。対応状況にかかわらず、直ちにエスカレーションが必要です。",
    "Alert severity is HIGH, but the threat is marked as handled and the endpoint is reported as isolated.":
        "アラートの重大度は HIGH（高）ですが、脅威は処理済みで、端末は隔離済みと報告されています。",
    "Alert severity is HIGH and the threat is marked as handled, but the endpoint has not been isolated.":
        "アラートの重大度は HIGH（高）で、脅威は処理済みですが、端末は隔離されていません。",
    "Alert severity is HIGH and the threat is not handled.":
        "アラートの重大度は HIGH（高）で、脅威は処理されていません。",
    "Alert severity is HIGH and the threat is not reported as handled.":
        "アラートの重大度は HIGH（高）で、脅威が処理済みであるとは報告されていません。",
    "Alert severity is MEDIUM and the threat is marked as handled.":
        "アラートの重大度は MEDIUM（中）で、脅威は処理済みです。",
    "Alert severity is MEDIUM and the threat has not been handled.":
        "アラートの重大度は MEDIUM（中）で、脅威は処理されていません。",
    "Alert severity is MEDIUM and the threat is not reported as handled.":
        "アラートの重大度は MEDIUM（中）で、脅威が処理済みであるとは報告されていません。",
    "Alert severity is LOW and the threat is marked as handled.":
        "アラートの重大度は LOW（低）で、脅威は処理済みです。",
    "Alert severity is LOW, but the threat is not handled.":
        "アラートの重大度は LOW（低）ですが、脅威は処理されていません。",
    "Alert severity is LOW, but the threat is not reported as handled, so it needs confirmation.":
        "アラートの重大度は LOW（低）ですが、脅威が処理済みであるとは報告されていないため、確認が必要です。",
    "The alert does not report a severity. Applying the MEDIUM risk safety default.":
        "アラートに重大度が含まれていないため、安全のため既定値の MEDIUM（中）を適用しました。",
    "The alert is reported as an outbreak.": "アウトブレイクとして報告されています。",
}


def _level(value: str) -> str:
    return _RISK_JA.get(value, value)


def _important_reason(reason: str) -> str:
    m = re.fullmatch(r"endpoint type '(.+)'", reason)
    if m:
        return f"端末種別「{m[1]}」"
    m = re.fullmatch(r"endpoint name '(.+)' matches important-asset pattern '(.+)'", reason)
    if m:
        return f"端末名「{m[1]}」が重要資産パターン「{m[2]}」に一致"
    return reason


_TEMPLATES = [
    (re.compile(r"(.+) Raised from (\w+) to (\w+)\.", re.S),
     lambda m: f"{to_japanese(m[1])}（{_level(m[2])} → {_level(m[3])} に引き上げ）"),
    (re.compile(r"(.+) Level already (\w+)\.", re.S),
     lambda m: f"{to_japanese(m[1])}（既に {_level(m[2])}）"),
    (re.compile(r"External threat intelligence \((.+)\) reports an indicator as (MALICIOUS|SUSPICIOUS)"
                r"( and the threat is not confirmed handled)?\."),
     lambda m: (f"外部の脅威インテリジェンス（{m[1]}）が指標を"
                f"{'悪性（MALICIOUS）' if m[2] == 'MALICIOUS' else '不審（SUSPICIOUS）'}と判定しています"
                f"{'（脅威の処理は未確認）' if m[3] else ''}。")),
    (re.compile(r"The detection is on an important endpoint \((.+)\) and is not confirmed handled\."),
     lambda m: f"重要端末（{_important_reason(m[1])}）での検知で、脅威の処理は未確認です。"),
    (re.compile(r"Ransomware-like indicator '(.+)' is present and the threat is not confirmed handled\."),
     lambda m: f"ランサムウェアの兆候「{m[1]}」があり、脅威の処理は未確認です。"),
    (re.compile(r"Ransomware-like indicator '(.+)' is present, although the threat is marked as handled\."),
     lambda m: f"ランサムウェアの兆候「{m[1]}」があります（脅威は処理済みと報告されています）。"),
    (re.compile(r"The alert reports (\d+) affected endpoints \(threshold (\d+)\)\."),
     lambda m: f"アラートは {m[1]} 台の端末への影響を報告しています（しきい値 {m[2]} 台）。"),
    (re.compile(r"The same detection has been seen on (\d+) distinct endpoints within (\d+) minutes "
                r"\(threshold (\d+)\)\."),
     lambda m: f"同一の検知が {m[2]} 分以内に {m[1]} 台の端末で確認されています（しきい値 {m[3]} 台）。"),
    (re.compile(r"Unknown alert severity '(.*)'\. Falling back to MEDIUM risk safety default\."),
     lambda m: f"不明な重大度「{m[1]}」です。安全のためリスクレベルを既定値の MEDIUM（中）にしました。"),
]


def to_japanese(detail: str) -> str:
    """The Japanese version of one risk-factor sentence, or the sentence unchanged."""
    if detail in _EXACT:
        return _EXACT[detail]
    for pattern, render in _TEMPLATES:
        m = pattern.fullmatch(detail)
        if m:
            return render(m)
    return detail
