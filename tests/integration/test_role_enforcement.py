"""
Role enforcement across the WHOLE route table.

Every route the app answers on must fall into exactly one class, and each class
accepts only its own credential:

    engineer  /dashboard/api/*, /status/*      X-Dashboard-Key
    client    /client/api/*                    X-Client-Session (login is the only open one)
    ingest    /webhook/*                       Authorization (webhook token)
    public    /health, /, /client, /static/*, /client/assets/*   (no data)

Routes are discovered from app.routes at test time, so routes other features add
later are covered automatically. A new path outside these classes fails
test_every_route_is_classified: classify it in tests/client_auth_helpers.py
deliberately (and gate it) rather than widening a prefix.
"""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from client_auth_helpers import (
    CLIENT_PUBLIC, ENGINEER, LOGIN_PATH, PASSWORD, WEBHOOK, admin_create, classify,
    enable_portal, http_probes, iter_routes, login, make_client_session, session_header,
    websocket_routes,
)
from src.config import settings
from src.main import app
from src.middleware import security

UNAUTHORIZED = {401}


def _send(client: TestClient, method: str, path: str, headers: dict):
    # A JSON body for methods that take one, so body-less 422s cannot mask the result.
    kwargs = {"json": {}} if method in ("POST", "PUT", "PATCH") else {}
    return client.request(method, path, headers=headers, **kwargs)


def test_every_route_is_classified():
    unclassified = sorted({r.path for r in iter_routes(app.routes) if classify(r.path) is None})
    assert not unclassified, (
        f"Routes outside every known class (engineer/client/ingest/public): {unclassified}. "
        "Put them under a gated prefix, or classify them in tests/client_auth_helpers.py.")


def test_inventory_is_not_empty():
    """Guards the guard: a route walker that silently finds nothing would pass everything."""
    paths = {r.path for r in iter_routes(app.routes)}
    assert {"/webhook/eset", "/dashboard/api/jobs", LOGIN_PATH, "/client/api/auth/me",
            "/dashboard/api/portal/users", "/dashboard/api/ws", "/health"} <= paths
    assert len(http_probes(app, "engineer")) > 20
    assert len(http_probes(app, "client")) >= 3


def test_engineer_routes_reject_client_session_and_webhook_token(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    token = make_client_session(client)
    failures = []
    for method, template, path in http_probes(app, "engineer"):
        for label, headers in (("client session", session_header(token)), ("webhook token", WEBHOOK),
                               ("no credential", {})):
            res = _send(client, method, path, headers)
            if res.status_code not in UNAUTHORIZED:
                failures.append(f"{method} {template} with {label} -> {res.status_code}")
    assert not failures, "\n".join(failures)
    # the session is still fine — rejections were not counted as guesses
    assert client.get("/client/api/auth/me", headers=session_header(token)).status_code == 200


def test_engineer_routes_check_the_key_before_validation(client: TestClient, monkeypatch):
    """No 422 schema leaks to a caller without the key: the prefix gate answers first."""
    enable_portal(monkeypatch)
    for method, template, path in http_probes(app, "engineer"):
        res = client.request(method, path, content=b"not json", headers={"content-type": "application/json"})
        assert res.status_code == 401, f"{method} {template} -> {res.status_code}"
    # unknown engineer paths do not reveal whether they exist either
    assert client.get("/dashboard/api/no-such-route").status_code == 401


def test_client_routes_reject_engineer_key_and_webhook_token(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    failures = []
    for method, template, path in http_probes(app, "client"):
        if template in CLIENT_PUBLIC:
            continue
        for label, headers in (("engineer key", ENGINEER), ("webhook token", WEBHOOK),
                               ("engineer key as session", {"X-Client-Session": ENGINEER["X-Dashboard-Key"]}),
                               ("webhook token as session", {"X-Client-Session": "test_token"}),
                               ("no credential", {})):
            res = _send(client, method, path, headers)
            if res.status_code not in UNAUTHORIZED:
                failures.append(f"{method} {template} with {label} -> {res.status_code}")
    assert not failures, "\n".join(failures) + (
        "\nClient routes must use Depends(require_client) (a dependency, so it runs before validation).")


def test_login_does_not_accept_other_credentials(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    for headers in (ENGINEER, WEBHOOK):
        res = client.post(LOGIN_PATH, json={"username": "", "password": ""}, headers=headers)
        assert res.status_code == 401
        assert "token" not in res.json()


def test_client_routes_closed_when_dashboard_key_blank(client: TestClient, monkeypatch):
    """A blank dashboard key leaves the engineering API open, so the whole portal
    — login included — must refuse service."""
    enable_portal(monkeypatch)
    token = make_client_session(client)
    monkeypatch.setattr(settings, "dashboard_access_key", "")
    for method, template, path in http_probes(app, "client"):
        res = _send(client, method, path, session_header(token))
        assert res.status_code == 404, f"{method} {template} -> {res.status_code}"
        assert res.json() == {"detail": "client portal disabled"}


def test_client_routes_closed_when_portal_switched_off(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    token = make_client_session(client)
    monkeypatch.setattr(settings, "client_portal_enabled", False)
    for method, template, path in http_probes(app, "client"):
        res = _send(client, method, path, session_header(token))
        assert res.status_code == 404, f"{method} {template} -> {res.status_code}"


def test_ingest_routes_reject_client_session_and_engineer_key(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    token = make_client_session(client)
    for method, template, path in http_probes(app, "ingest"):
        for headers in (session_header(token), ENGINEER,
                        {"Authorization": f"Bearer {token}"},
                        {"Authorization": f"Bearer {ENGINEER['X-Dashboard-Key']}"}):
            res = _send(client, method, path, headers)
            assert res.status_code == 401, f"{method} {template} {list(headers)} -> {res.status_code}"
        security.auth_limiter.reset()


def test_engineer_key_still_works_alongside(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    token = make_client_session(client)
    assert client.get("/dashboard/api/jobs", headers=ENGINEER).status_code == 200
    # a client session does not add anything to a request that has the key, nor replace it
    assert client.get("/dashboard/api/jobs", headers={**ENGINEER, **session_header(token)}).status_code == 200
    assert client.get("/client/api/auth/me", headers={**ENGINEER, **session_header(token)}).status_code == 200


def test_websockets_reject_client_session(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    token = make_client_session(client)
    ws_paths = websocket_routes(app)
    assert "/dashboard/api/ws" in ws_paths
    for path in ws_paths:
        assert classify(path) == "engineer", f"websocket {path} outside the engineer prefix"
        for headers in (session_header(token), {"Authorization": f"Bearer {token}"}):
            with pytest.raises(WebSocketDisconnect) as rejected:
                with client.websocket_connect(path, headers=headers):
                    pass
            assert rejected.value.code == 4401
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"{path}?key={token}"):
                pass


def test_client_api_has_no_store_and_same_origin(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    admin_create(client, "origin.user")
    res = client.post(LOGIN_PATH, json={"username": "origin.user", "password": PASSWORD},
                      headers={"Origin": "https://evil.example"})
    assert res.status_code == 403 and res.headers["cache-control"] == "no-store"
    same = client.post(LOGIN_PATH, json={"username": "origin.user", "password": PASSWORD},
                       headers={"Origin": "http://testserver"})
    assert same.status_code == 200 and same.headers["cache-control"] == "no-store"
    # non-browser callers send no Origin and are unaffected, as on /dashboard/api/
    token = login(client, "origin.user")
    res = client.get("/client/api/auth/me", headers=session_header(token))
    assert res.headers["cache-control"] == "no-store"
    assert res.headers["x-frame-options"] == "DENY"
    # a GET is never origin-checked
    assert client.get("/client/api/auth/me", headers={**session_header(token),
                                                      "Origin": "https://evil.example"}).status_code == 200


def test_public_routes_need_no_credential(client: TestClient, monkeypatch):
    enable_portal(monkeypatch)
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
