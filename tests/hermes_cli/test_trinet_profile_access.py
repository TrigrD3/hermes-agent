"""TRINET fork: an IdP sign-in reaches only the profiles its groups map to (profile_access.py)."""
from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from hermes_cli.dashboard_auth import Session
from hermes_cli.dashboard_auth import profile_access as pa
from hermes_cli.isolated_scope import request_profiles, restrict_request_profiles, scope_to_launch_profile

POLICY = {"admin_groups": ["hermes-admin"],
          "groups": {"writers": ["penulis"], "planners": ["perencana", "penulis"]}}


def _session(*groups: str, provider: str = "self_hosted") -> Session:
    return Session(user_id="u1", email="a@example.com", display_name="A", org_id="", provider=provider,
                   expires_at=int(time.time()) + 600, access_token="t", refresh_token="", groups=tuple(groups))


@pytest.fixture
def profiles():
    from hermes_constants import get_default_hermes_root
    root = get_default_hermes_root()
    for name in ("penulis", "perencana", "pemeriksa"):
        home = root / "profiles" / name
        home.mkdir(parents=True, exist_ok=True)
        (home / "config.yaml").write_text("{}\n", encoding="utf-8")
    return root


@pytest.fixture
def policy(monkeypatch):
    monkeypatch.setattr(pa, "_policy", lambda: POLICY)


def _request(path: str, *, method: str = "GET", query: str = "", body: bytes = b"", json_body: bool = False):
    from starlette.requests import Request
    headers = [(b"content-type", b"application/json")] if json_body else []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    return Request({"type": "http", "method": method, "path": path, "query_string": query.encode(),
                    "headers": headers}, receive)


# ---- who gets what ----

def test_no_policy_keeps_upstream_access(monkeypatch):
    monkeypatch.setattr(pa, "_policy", dict)
    assert pa.allowed_profiles(_session("writers")) is None


def test_groups_map_to_profiles_default_first(policy):
    assert pa.allowed_profiles(_session("writers")) == ("penulis",)
    assert pa.allowed_profiles(_session("planners")) == ("perencana", "penulis")


def test_admin_and_operator_token_are_unrestricted(policy):
    assert pa.allowed_profiles(_session("hermes-admin", "writers")) is None
    assert pa.allowed_profiles(_session(provider="session-token")) is None


def test_unmapped_user_gets_no_profile(policy):
    assert pa.allowed_profiles(_session("someone-else")) == ()


def test_policy_reads_config_yaml(profiles):
    (profiles / "config.yaml").write_text(
        "dashboard:\n  oauth:\n    profile_access:\n      groups:\n        writers: [penulis]\n", encoding="utf-8")
    assert pa.allowed_profiles(_session("writers")) == ("penulis",)


def test_keycloak_full_path_groups_are_stripped(monkeypatch):
    import plugins.dashboard_auth.self_hosted as oidc_plugin
    provider = oidc_plugin.SelfHostedOIDCProvider(issuer="https://idp.example.com/realms/x", client_id="hermes")
    claims = {"sub": "u1", "exp": int(time.time()) + 600, "iss": "https://idp.example.com/realms/x",
              "groups": ["/writers", "hermes-admin"]}
    assert provider._session("tok", "", claims).groups == ("writers", "hermes-admin")


# ---- REST rules ----

@pytest.mark.parametrize("path,method,query", [
    ("/api/config", "GET", "profile=perencana"),
    ("/api/profiles/perencana/soul", "GET", ""),
    ("/api/profiles", "POST", ""),
    ("/api/profiles/penulis", "DELETE", ""),
    ("/api/profiles/penulis", "PATCH", ""),
    ("/api/profiles/import", "POST", ""),
    ("/api/profiles/active", "POST", ""),
    ("/api/profiles/sessions", "GET", "profile=pemeriksa"),
    ("/api/profiles/sessions/sidebar", "GET", "recents_profile=pemeriksa"),
])
@pytest.mark.asyncio
async def test_rest_refuses_other_profiles_and_registry_writes(profiles, path, method, query):
    with pytest.raises(PermissionError):
        await pa.check_request(_request(path, method=method, query=query), ("penulis",))


@pytest.mark.parametrize("path,query", [
    ("/api/config", ""), ("/api/config", "profile=current"), ("/api/config", "profile=penulis"),
    ("/api/profiles", ""), ("/api/profiles/active", ""), ("/api/profiles/penulis/soul", ""),
    ("/api/profiles/sessions", "profile=all"), ("/api/cron/jobs", ""),
])
@pytest.mark.asyncio
async def test_rest_allows_own_and_implicit(profiles, path, query):
    await pa.check_request(_request(path, query=query), ("penulis",))


@pytest.mark.asyncio
async def test_rest_checks_json_body_profile(profiles):
    req = _request("/api/skills/toggle", method="POST", body=b'{"profile": "perencana"}', json_body=True)
    with pytest.raises(PermissionError):
        await pa.check_request(req, ("penulis",))


@pytest.mark.asyncio
async def test_unmapped_user_reaches_only_sign_in_plumbing(profiles):
    await pa.check_request(_request("/api/auth/me"), ())
    with pytest.raises(PermissionError):
        await pa.check_request(_request("/api/config"), ())


def test_listings_narrow_to_allowed():
    names = ["default", "penulis", "perencana"]
    assert scope_to_launch_profile(names) == names
    with restrict_request_profiles(("penulis",)):
        assert scope_to_launch_profile(names) == ["penulis"]
    assert scope_to_launch_profile(names) == names


def test_middleware_403s_and_binds_default_home(profiles, policy):
    from hermes_constants import get_hermes_home

    async def where(request):
        return JSONResponse({"home": str(get_hermes_home()), "allowed": request_profiles()})

    class FakeGate(BaseHTTPMiddleware):  # stands in for the dashboard auth gate
        async def dispatch(self, request, call_next):
            request.state.session = _session("writers")
            return await call_next(request)

    app = Starlette(routes=[Route("/api/config", where)])
    app.add_middleware(BaseHTTPMiddleware, dispatch=pa.profile_access_middleware)
    app.add_middleware(FakeGate)
    client = TestClient(app)
    assert client.get("/api/config?profile=perencana").status_code == 403
    body = client.get("/api/config").json()
    assert Path(body["home"]).resolve() == (profiles / "profiles" / "penulis").resolve()
    assert body["allowed"] == ["penulis"]


# ---- sockets ----

def _ws(access):
    identity = {"user_id": "u1", "provider": "self_hosted"}
    if access is not None:
        identity["profile_access"] = access
    return SimpleNamespace(_hermes_auth_identity=identity)


def test_ws_profile(profiles):
    assert pa.ws_profile(_ws(None), "perencana") == "perencana"
    assert pa.ws_profile(_ws(["penulis"]), None) == "penulis"
    assert pa.ws_profile(_ws(["penulis"]), "current") == "penulis"
    assert pa.ws_profile(_ws(["penulis"]), "penulis") == "penulis"
    with pytest.raises(PermissionError):
        pa.ws_profile(_ws(["penulis"]), "perencana")
    with pytest.raises(PermissionError):
        pa.ws_profile(_ws([]), None)


def test_gateway_rpc_runs_in_allowed_profile(profiles, monkeypatch):
    from tui_gateway import ws_legacy_fallback as fb
    seen = {}

    def fake_legacy(server, req, transport, actor):
        seen.update(home=actor.profile_id, allowed=request_profiles())
        return {"result": "ok"}

    monkeypatch.setattr(fb, "dispatch_legacy", fake_legacy)
    server = SimpleNamespace(
        _profile_home=lambda name: profiles / "profiles" / name if name != "default" else None,
        _launch_home=lambda: profiles)
    refused = fb.dispatch_profile_restricted(server, {"id": 1, "params": {"profile": "perencana"}}, None, ("penulis",))
    assert refused["error"]["code"] == 4064 and not seen
    assert fb.dispatch_profile_restricted(server, {"id": 2, "params": {}}, None, ("penulis",)) == {"result": "ok"}
    assert seen == {"home": str(profiles / "profiles" / "penulis"), "allowed": ("penulis",)}


def test_plugin_calls_run_on_the_launch_copy(profiles, policy):
    from hermes_constants import get_hermes_home

    async def where(request):
        return JSONResponse({"home": str(get_hermes_home()), "query": request.url.query,
                             "allowed": request_profiles()})

    class FakeGate(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.session = _session("writers")
            return await call_next(request)

    app = Starlette(routes=[Route("/api/plugins/marketing/agents", where),
                            Route("/api/dashboard/plugins/marketing/visibility", where, methods=["POST"])])
    app.add_middleware(BaseHTTPMiddleware, dispatch=pa.profile_access_middleware)
    app.add_middleware(FakeGate)
    client = TestClient(app)
    body = client.get("/api/plugins/marketing/agents?profile=penulis&board=marketing").json()
    assert body["query"] == "board=marketing" and body["allowed"] == ["penulis"]
    assert Path(body["home"]).resolve() == profiles.resolve()
    assert client.get("/api/plugins/marketing/agents?profile=perencana").status_code == 403
    assert client.post("/api/dashboard/plugins/marketing/visibility").status_code == 403


def test_policy_is_the_launch_profiles_even_when_re_homed(profiles):
    """A request re-homed to penulis must still read the root config's policy (its own has none)."""
    (profiles / "config.yaml").write_text(
        "dashboard:\n  oauth:\n    profile_access:\n      groups:\n        writers: [penulis]\n", encoding="utf-8")
    with pa.request_scope(("penulis",)):
        assert pa.allowed_profiles(_session("writers")) == ("penulis",)


def test_unreadable_policy_fails_closed(monkeypatch):
    def broken():
        raise pa._PolicyUnreadable()
    monkeypatch.setattr(pa, "_policy", broken)
    assert pa.allowed_profiles(_session("hermes-admin")) == ()
    assert pa.allowed_profiles(_session(provider="session-token")) is None


@pytest.mark.asyncio
async def test_collection_routes_follow_their_methods(profiles):
    with pytest.raises(PermissionError):  # no such collection verb: it names a profile called "sessions"
        await pa.check_request(_request("/api/profiles/sessions", method="DELETE"), ("penulis",))
    await pa.check_request(_request("/api/profiles/sessions/pull-requests", method="POST"), ("penulis",))


def test_cron_job_lookup_skips_other_profiles(monkeypatch):
    from hermes_cli import web_server_cron as cron
    monkeypatch.setattr(cron, "_cron_profile_dicts", lambda: [{"name": "perencana"}, {"name": "penulis"}])
    monkeypatch.setattr(cron, "_call_cron_for_profile",
                        lambda name, *_: [{"id": "job-1"}] if name == "perencana" else [])
    assert cron._find_cron_job_profile("job-1") == "perencana"
    with restrict_request_profiles(("penulis",)):
        assert cron._find_cron_job_profile("job-1") is None


def test_real_app_scopes_a_signed_in_user(profiles, monkeypatch):
    """The real middleware order: the auth gate's session reaches the profile gate and the routes."""
    (profiles / "config.yaml").write_text(
        "dashboard:\n  oauth:\n    profile_access:\n      groups:\n        writers: [penulis]\n", encoding="utf-8")
    from hermes_cli.dashboard_auth import middleware as gate
    from hermes_cli.dashboard_auth.ws_tickets import consume_ticket
    from hermes_cli.web_server import app

    async def signed_in(request, call_next):
        request.state.session = _session("writers")
        return await call_next(request)

    monkeypatch.setattr(gate, "gated_auth_middleware", signed_in)
    monkeypatch.setattr(app.state, "auth_required", True, raising=False)
    client = TestClient(app)
    assert [p["name"] for p in client.get("/api/profiles").json()["profiles"]] == ["penulis"]
    assert client.get("/api/profiles/active").json()["current"] == "penulis"
    assert client.get("/api/profiles/perencana/soul").status_code == 403
    ticket = client.post("/api/auth/ws-ticket").json()["ticket"]
    assert consume_ticket(ticket)["profile_access"] == ["penulis"]
