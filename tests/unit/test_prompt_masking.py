from src.services.ai.prompt_masking import mask_alert_for_prompt


def _base_data(**overrides) -> dict:
    data = {
        "source": "ESET_PROTECT_CLOUD",
        "event_type": "Threat Detection",
        "alert_id": "alert-1",
        "detection_uuid": "UNKNOWN",
        "target_uuid": "UNKNOWN",
        "occurred_at": "2026-01-01T00:00:00Z",
        "severity": "HIGH",
        "detection_name": "Win32/TrojanDownloader.Agent.YHV",
        "endpoint_name": "FINANCE-PC-09",
        "endpoint_type": "Server",
        "user_name": "charlie.brown",
        "os_name": "Windows Server 2022",
        "action_taken": "Connection terminated",
        "threat_handled": "false",
        "isolation_status": "false",
        "object_type": "Process",
        "object_uri": r"C:\Users\charlie.brown\AppData\Local\Temp\evil.exe",
        "file_hash": "a4f5b6c7d8e9",
        "url": "http://malicious.example/shell",
        "ip_address": "185.220.101.5",
        "domain": "malicious.example",
        "raw_subject": "High Risk Trojan Activity",
        "raw_content": "A connection to a known C2 server was detected.",
    }
    data.update(overrides)
    return data


def test_user_name_is_masked():
    masked, changed = mask_alert_for_prompt(_base_data())
    assert masked["user_name"] != "charlie.brown"
    assert masked["user_name"].startswith("c")
    assert masked["user_name"].endswith("n")
    assert "charlie.brown" not in masked["user_name"]
    assert "user_name" in changed


def test_object_uri_username_segment_is_masked_but_filename_kept():
    masked, changed = mask_alert_for_prompt(_base_data())
    assert "charlie.brown" not in masked["object_uri"]
    assert r"\Users\c" in masked["object_uri"]
    assert "evil.exe" in masked["object_uri"]  # the actually-useful triage signal
    assert "object_uri" in changed


def test_fields_needed_for_triage_are_left_unmasked():
    masked, _ = mask_alert_for_prompt(_base_data())
    assert masked["endpoint_name"] == "FINANCE-PC-09"
    assert masked["ip_address"] == "185.220.101.5"
    assert masked["url"] == "http://malicious.example/shell"
    assert masked["domain"] == "malicious.example"
    assert masked["file_hash"] == "a4f5b6c7d8e9"


def test_unknown_values_are_left_alone():
    masked, changed = mask_alert_for_prompt(_base_data(user_name="UNKNOWN", object_uri="UNKNOWN"))
    assert masked["user_name"] == "UNKNOWN"
    assert masked["object_uri"] == "UNKNOWN"
    assert changed == []


def test_object_uri_without_a_user_profile_segment_is_unchanged():
    masked, changed = mask_alert_for_prompt(_base_data(object_uri=r"C:\Windows\System32\cmd.exe"))
    assert masked["object_uri"] == r"C:\Windows\System32\cmd.exe"
    assert "object_uri" not in changed


def test_original_dict_is_never_mutated():
    original = _base_data()
    snapshot = dict(original)
    mask_alert_for_prompt(original)
    assert original == snapshot


def test_short_user_name_is_fully_masked_not_left_readable():
    masked, changed = mask_alert_for_prompt(_base_data(user_name="al"))
    assert masked["user_name"] == "**"
    assert "user_name" in changed


# --------------------------- mask_raw_payload_for_prompt ---------------------------
# Covers the raw/arbitrary-shaped original payload, distinct from the fixed-field
# normalized-alert masking above: this platform accepts alerts in any JSON shape,
# so PII in the original payload is masked by key name at any nesting depth, not
# only at the one top-level "user_name" field mask_alert_for_prompt knows about.

def test_raw_payload_masks_known_key_at_any_depth():
    from src.services.ai.prompt_masking import mask_raw_payload_for_prompt

    payload = {
        "username": "john.smith",
        "detail": {"owner": "jane.doe", "host": "PC-01"},
        "list": [{"account": "bob.jones"}],
    }
    masked, changed = mask_raw_payload_for_prompt(payload)

    assert masked["username"] == "j********h"
    assert masked["detail"]["owner"] == "j******e"
    assert masked["detail"]["host"] == "PC-01"  # not a masked key name
    assert masked["list"][0]["account"] == "b*******s"
    assert set(changed) == {"username", "detail.owner", "list[0].account"}


def test_raw_payload_masking_is_case_insensitive_on_key_name():
    from src.services.ai.prompt_masking import mask_raw_payload_for_prompt

    masked, changed = mask_raw_payload_for_prompt({"UserName": "Alice"})
    assert masked["UserName"] == "A***e"
    assert changed == ["UserName"]


def test_raw_payload_masking_leaves_unrelated_keys_and_types_untouched():
    from src.services.ai.prompt_masking import mask_raw_payload_for_prompt

    payload = {"ip_address": "203.0.113.5", "count": 3, "active": True, "tags": None}
    masked, changed = mask_raw_payload_for_prompt(payload)
    assert masked == payload
    assert changed == []


def test_raw_payload_masking_does_not_mutate_input():
    from src.services.ai.prompt_masking import mask_raw_payload_for_prompt

    original = {"user": "jane.doe"}
    snapshot = dict(original)
    mask_raw_payload_for_prompt(original)
    assert original == snapshot
