"""
Helpers for the client-portal auth / role-enforcement tests (kept out of
conftest on purpose; import with `from client_auth_helpers import ...`).
"""
import re
from typing import Any, Iterator

from fastapi.testclient import TestClient

from src.config import settings

# Long enough to satisfy portal_guard (>= 16 characters).
ENGINEER_KEY = "engineer-key-0123456789abcdef"
ENGINEER = {"X-Dashboard-Key": ENGINEER_KEY}
WEBHOOK = {"Authorization": "Bearer test_token"}  # conftest sets the token to test_token
PASSWORD = "correct horse battery"

LOGIN_PATH = "/client/api/auth/login"
ADMIN_USERS = "/dashboard/api/portal/users"


def enable_portal(monkeypatch, key: str = ENGINEER_KEY) -> None:
    """Dashboard key configured + portal switched on (env default; no DB override)."""
    monkeypatch.setattr(settings, "dashboard_access_key", key)
    monkeypatch.setattr(settings, "client_portal_enabled", True)


def session_header(token: str) -> dict[str, str]:
    return {"X-Client-Session": token}


def admin_create(client: TestClient, username: str, password: str | None = PASSWORD,
                 display_name: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"username": username}
    if password is not None:
        body["password"] = password
    if display_name is not None:
        body["display_name"] = display_name
    res = client.post(ADMIN_USERS, json=body, headers=ENGINEER)
    assert res.status_code == 201, res.text
    return res.json()


def login(client: TestClient, username: str, password: str = PASSWORD) -> str:
    res = client.post(LOGIN_PATH, json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return res.json()["token"]


def make_client_session(client: TestClient, username: str = "probe.user") -> str:
    """Creates a client account through the engineer API and logs it in."""
    admin_create(client, username)
    return login(client, username)


class LogRecorder:
    """Stand-in for a module's structlog logger: records (level, event, fields)."""

    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []

    def __getattr__(self, level: str):
        def log(event: str, **fields: Any) -> None:
            self.records.append((level, event, fields))
        return log

    def events(self) -> list[str]:
        return [event for _, event, _ in self.records]

    def find(self, event: str) -> list[dict[str, Any]]:
        return [fields for _, ev, fields in self.records if ev == event]

    def dump(self) -> str:
        return repr(self.records)


# ------------------------------ route inventory ------------------------------

def iter_routes(routes: Any) -> Iterator[Any]:
    """Every leaf route/mount the app answers on, unwrapping included routers
    the same way main._resolved_route_paths does."""
    for r in routes:
        if isinstance(getattr(r, "path", None), str):
            yield r
            continue
        nested = getattr(r, "original_router", None) or getattr(r, "router", None)
        if nested is not None and hasattr(nested, "routes"):
            yield from iter_routes(nested.routes)
        elif hasattr(r, "routes"):
            yield from iter_routes(r.routes)


_PARAM_RE = re.compile(r"\{[^}]+\}")


def fill_path(path: str) -> str:
    """Substitutes every path parameter ({id}, {rest:path}) with a dummy value."""
    return _PARAM_RE.sub("dummy", path)


DOCS_PATHS = {"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}
PUBLIC_EXACT = {"/health", "/", "/client", "/client/", "/static"}
PUBLIC_PREFIXES = ("/static/", "/client/assets")
# Client routes reachable without a session.
CLIENT_PUBLIC = {LOGIN_PATH}


def classify(path: str) -> str | None:
    """engineer | client | ingest | public | None (unclassified — a test failure)."""
    if path.startswith(("/dashboard/api/", "/status/")):
        return "engineer"
    if path.startswith("/client/api/"):
        return "client"
    if path.startswith("/webhook/"):
        return "ingest"
    if path in PUBLIC_EXACT or path.startswith(PUBLIC_PREFIXES):
        return "public"
    if path in DOCS_PATHS and settings.enable_api_docs:
        return "public"
    return None


def http_probes(app: Any, cls: str) -> list[tuple[str, str, str]]:
    """(method, template path, concrete path) for every HTTP route of a class."""
    out = []
    for r in iter_routes(app.routes):
        methods = getattr(r, "methods", None)
        if not methods or classify(r.path) != cls:
            continue
        for m in sorted(methods - {"HEAD", "OPTIONS"}):
            out.append((m, r.path, fill_path(r.path)))
    return out


def websocket_routes(app: Any) -> list[str]:
    from starlette.routing import WebSocketRoute
    return [r.path for r in iter_routes(app.routes)
            if isinstance(r, WebSocketRoute) or type(r).__name__ == "APIWebSocketRoute"]
