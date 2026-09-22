import pytest

from src.services.threat_intel.virustotal import _indicator_is_safe
from src.services.threat_intel.abuseipdb import AbuseIPDBProvider


@pytest.mark.parametrize("kind,value", [
    ("file", "a" * 64 + "\n"),
    ("file", "../../../intelligence/search?query=x"),
    ("ip", "1.2.3.4?query=x"),
    ("ip", "fe80::1%a?query=x"),
    ("ip", "fe80::1%a#fragment"),
])
def test_malformed_indicators_cannot_rewrite_vt_request(kind, value):
    assert not _indicator_is_safe(value, kind)


@pytest.mark.parametrize("kind,value", [
    ("file", "a" * 32), ("file", "A" * 40), ("file", "f" * 64),
    ("ip", "1.2.3.4"), ("ip", "2001:db8::1"),
])
def test_valid_indicators_are_accepted(kind, value):
    assert _indicator_is_safe(value, kind)


@pytest.mark.parametrize("value", ["not-an-ip", "1.2.3.4?query=x", "fe80::1%eth0"])
async def test_invalid_abuseipdb_indicators_never_contact_service(value, monkeypatch):
    import httpx
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-only-key")

    def forbidden_client(*args, **kwargs):
        pytest.fail("invalid indicator must be rejected before any network client is created")

    monkeypatch.setattr(httpx, "AsyncClient", forbidden_client)
    result = await AbuseIPDBProvider()._query_real(value)
    assert result.status == "UNKNOWN" and result.error == "Not a valid IP address"
