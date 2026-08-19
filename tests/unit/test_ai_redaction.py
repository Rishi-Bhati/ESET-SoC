from src.services.ai.redaction import redact_value, scan_text


def test_generic_secret_assignment_is_fully_redacted():
    text = 'config: api_key: sk-abcdefghijklmnopqrstuvwxyz123456 loaded'
    redacted, findings = scan_text(text)
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "[REDACTED: SECRET]" in redacted
    assert any(f.category == "GENERIC_SECRET_ASSIGNMENT" for f in findings)


def test_password_assignment_is_redacted_but_key_name_kept():
    redacted, findings = scan_text("password: hunter2live!")
    assert "hunter2live" not in redacted
    assert redacted.startswith("password:")
    assert findings[0].category == "GENERIC_SECRET_ASSIGNMENT"


def test_private_key_is_fully_redacted():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBAK...redacted-body...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    redacted, findings = scan_text(f"here is a key:\n{pem}\nend")
    assert "MIIBOgIBAAJBAK" not in redacted
    assert "[REDACTED: PRIVATE_KEY]" in redacted
    assert findings[0].category == "PRIVATE_KEY"


def test_connection_string_is_fully_redacted():
    redacted, findings = scan_text("DB_URL=postgres://svc_user:sup3rSecret@db.internal:5432/prod")
    assert "sup3rSecret" not in redacted
    assert "[REDACTED: CONNECTION_STRING]" in redacted


def test_bearer_token_is_redacted_but_scheme_kept():
    redacted, findings = scan_text('Authorization: Bearer abcdefghijklmnop1234567890')
    assert "abcdefghijklmnop1234567890" not in redacted
    assert "Bearer [REDACTED: TOKEN]" in redacted


def test_aws_access_key_is_partially_masked():
    redacted, findings = scan_text("AKIAABCDEFGHIJKLMNOP")
    assert redacted != "AKIAABCDEFGHIJKLMNOP"
    assert redacted.startswith("AKI")
    assert "*" in redacted
    assert findings[0].category == "AWS_ACCESS_KEY"


def test_google_api_key_is_partially_masked():
    key = "AIza" + "S" * 35
    redacted, findings = scan_text(key)
    assert key not in redacted
    assert redacted.startswith("AIz")
    assert findings[0].category == "GOOGLE_API_KEY"


def test_jwt_is_fully_redacted():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzYXNpZ25hdHVyZQ"
    redacted, findings = scan_text(f"token={jwt}")
    assert jwt not in redacted
    assert "[REDACTED: JWT]" in redacted


def test_email_is_partially_masked_not_removed():
    redacted, findings = scan_text("contact john.doe@example.com for details")
    assert "john.doe@example.com" not in redacted
    assert "@example.com" in redacted  # domain kept for context
    assert findings[0].category == "EMAIL_PII"


def test_credit_card_shaped_number_is_fully_redacted():
    redacted, findings = scan_text("card 4111 1111 1111 1111 was used")
    assert "4111 1111 1111 1111" not in redacted
    assert "[REDACTED: CREDIT_CARD]" in redacted


def test_clean_text_has_no_findings():
    text = "Win32/TrojanDownloader.Agent.YHV detected on FINANCE-PC-09"
    redacted, findings = scan_text(text)
    assert redacted == text
    assert findings == []


def test_redact_value_recurses_through_dict_and_list_and_tracks_paths():
    payload = {
        "normalized_alert": {
            "raw_content": "leaked password: hunter2live!",
            "endpoint_name": "FINANCE-PC-09",
        },
        "notes": ["contact admin@example.com", "nothing sensitive here"],
    }
    redacted, findings = redact_value(payload)
    assert "hunter2live" not in str(redacted)
    assert redacted["normalized_alert"]["endpoint_name"] == "FINANCE-PC-09"  # untouched
    paths = {p for p, _ in findings}
    assert "normalized_alert.raw_content" in paths
    assert "notes[0]" in paths


def test_redact_value_passes_through_non_string_types_unchanged():
    payload = {"count": 5, "ok": True, "nothing": None, "ratio": 1.5}
    redacted, findings = redact_value(payload)
    assert redacted == payload
    assert findings == []
