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
