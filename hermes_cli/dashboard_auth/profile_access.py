"""TRINET fork: limit an IdP dashboard sign-in to the profiles its groups map to.

Opt-in through ``config.yaml``; with no ``dashboard.oauth.profile_access`` block every signed-in
user keeps upstream's whole-host access::

    dashboard:
      oauth:
        profile_access:
          admin_groups: [hermes-admin]      # see and manage every profile
          groups:                           # IdP group -> profiles; the first one listed is the default
            marketing-writers: [penulis]

A user in no listed group gets no profile. This is dashboard scoping, NOT isolation: profiles share
one OS user, so a shell or an agent tool can still read every profile (``isolated_scope.py``).
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import parse_qsl, urlencode

from starlette.responses import JSONResponse

_log = logging.getLogger(__name__)

#: Providers whose sessions are the operator's own credential, never a person to scope.
_UNSCOPED_PROVIDERS = frozenset({"session-token"})
#: ``/api/profiles/<suffix>`` collections a scoped user may call; their selectors are checked as query params.
_READ_COLLECTIONS = frozenset({"sessions", "sessions/sidebar", "projects/tree", "sessions/pull-requests"})
#: Selector values that name no single profile: the request's own (bound below) or all of them,
#: which ``isolated_scope.scope_to_launch_profile`` narrows to the allowed ones.
_IMPLICIT = frozenset({"", "current", "all"})
#: What a user with no mapped profile may still call: sign-in plumbing and the public status.
_NO_PROFILE_PATHS = ("/api/auth/", "/api/status")
#: Plugin routes a scoped user reaches on the launch profile's copy: upstream runs a plugin in the
#: selected profile's plugin host, where a root-installed plugin (the Marketing tab) reads that
#: profile's HERMES_HOME. The plugin scopes itself with ``isolated_scope.request_profiles()``.
_HOST_LEVEL_PATHS = ("/api/plugins/", "/api/dashboard/plugins")


class _PolicyUnreadable(Exception):
    pass


def _policy() -> dict[str, Any]:
    """The launch profile's block: a request re-homed to the user's profile must not read that
    profile's config.yaml, which has none."""
    from hermes_cli.config import cfg_get, load_config_readonly
    from hermes_constants import get_process_hermes_home, reset_hermes_home_override, set_hermes_home_override
    token = set_hermes_home_override(str(get_process_hermes_home()))
    try:
        section = cfg_get(load_config_readonly(), "dashboard", "oauth", "profile_access", default=None)
    except Exception as exc:
        raise _PolicyUnreadable from exc
    finally:
        reset_hermes_home_override(token)
    return section if isinstance(section, dict) else {}


def _names(values: Any) -> list[str]:
    from hermes_cli.profiles import normalize_profile_name
    if isinstance(values, str):
        values = [values]
    return [normalize_profile_name(str(v).strip()) for v in (values or []) if str(v).strip()]


def allowed_profiles(session: Any) -> Optional[tuple[str, ...]]:
    """The profiles *session* may use, default first; ``None`` = unrestricted."""
    if session is None or getattr(session, "provider", "") in _UNSCOPED_PROVIDERS:
        return None
    try:
        policy = _policy()
    except _PolicyUnreadable:  # fail closed: nobody but the operator token gets a profile
        _log.exception("profile_access: config unreadable; refusing every scoped sign-in")
        return ()
    if not policy:
        return None
    groups = set(getattr(session, "groups", ()) or ())
    if groups & set(_names_raw(policy.get("admin_groups"))):
        return None
    mapping = policy.get("groups") if isinstance(policy.get("groups"), dict) else {}
    allowed: list[str] = []
    for group, profiles in mapping.items():
        if str(group) in groups:
            allowed.extend(n for n in _names(profiles) if n not in allowed)
    return tuple(allowed)


def _names_raw(values: Any) -> list[str]:
    if isinstance(values, str):
        values = [values]
    return [str(v) for v in (values or [])]


def _profile_dir(name: str) -> Optional[Path]:
    from hermes_cli import profiles as profiles_mod
    try:
        profiles_mod.validate_profile_name(profiles_mod.normalize_profile_name(name))
        if not profiles_mod.profile_exists(name):
            return None
        return Path(profiles_mod.get_profile_dir(name)).resolve()
    except ValueError:
        return None


def is_allowed(value: Any, allowed: Iterable[str], *, implicit_ok: bool = True) -> bool:
    """True when the selector *value* names an allowed profile (or, if *implicit_ok*, none)."""
    if value is None or (isinstance(value, str) and value.strip().lower() in _IMPLICIT):
        return implicit_ok
    if not isinstance(value, str):
        return False
    target = _profile_dir(value.strip())
    return target is not None and any(target == _profile_dir(name) for name in allowed)


def _check(value: Any, allowed: tuple[str, ...], *, implicit_ok: bool = True) -> None:
    if not is_allowed(value, allowed, implicit_ok=implicit_ok):
        raise PermissionError("profile_access_denied")


async def check_request(request: Any, allowed: tuple[str, ...], *, public: bool = False) -> None:
    """Raise ``PermissionError`` when this REST call reaches past *allowed*."""
    path = request.url.path.rstrip("/")
    if not allowed and not public and not path.startswith(_NO_PROFILE_PATHS):
        raise PermissionError("profile_access_denied")
    for key in ("profile", "recents_profile"):
        for value in request.query_params.getlist(key):
            _check(value, allowed)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and (
            content_type == "application/json"
            or (content_type.startswith("application/") and content_type.endswith("+json"))):
        try:
            body = await request.json()
        except (ValueError, UnicodeError):
            body = None  # route validation still owns malformed JSON
        if isinstance(body, dict) and "profile" in body:
            _check(body["profile"], allowed)
    if path.startswith("/api/dashboard/plugins") and request.method not in {"GET", "HEAD"}:
        raise PermissionError("profile_access_denied")  # installing / hiding plugins is host-wide
    if path == "/api/profiles":
        if request.method != "GET":  # creating a profile is an admin's job
            raise PermissionError("profile_access_denied")
    elif path.startswith("/api/profiles/"):
        from hermes_cli.dashboard_auth.native_http import profile_collection_route
        collection = profile_collection_route(path, request.method)
        if collection in _READ_COLLECTIONS or (collection == "active" and request.method == "GET"):
            return  # selectors checked above; "all" is narrowed by the listing scope
        if collection is not None:  # import, or setting the host-wide sticky default
            raise PermissionError("profile_access_denied")
        suffix = path.removeprefix("/api/profiles/")
        if request.method in {"PATCH", "DELETE"} and "/" not in suffix:
            raise PermissionError("profile_access_denied")  # rename / delete
        _check(suffix.split("/", 1)[0], allowed, implicit_ok=False)


@contextmanager
def request_scope(allowed: tuple[str, ...], *, bind_home: bool = True):
    """Bind *allowed* as this request's listing scope and, with *bind_home*, its default profile
    as the home of a request that names none."""
    from hermes_cli.isolated_scope import restrict_request_profiles
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override
    home = _profile_dir(allowed[0]) if allowed and bind_home else None
    with restrict_request_profiles(allowed):
        token = set_hermes_home_override(str(home)) if home is not None else None
        try:
            yield
        finally:
            if token is not None:
                reset_hermes_home_override(token)


async def profile_access_middleware(request: Any, call_next):
    """REST gate, run right after the dashboard auth gate stamped ``request.state.session``."""
    session, public = getattr(request.state, "session", None), False
    if session is None and getattr(request.app.state, "auth_required", False):
        # The gate skips public paths (/api/status, /api/dashboard/plugins); a signed-in caller
        # still gets its own scope there.
        from hermes_cli.dashboard_auth.middleware import _path_is_public, peek_session
        public = _path_is_public(request.url.path)
        session = peek_session(request) if public else None
    allowed = allowed_profiles(session)
    if allowed is None or not request.url.path.startswith("/api/"):
        return await call_next(request)
    try:
        await check_request(request, allowed, public=public)
    except PermissionError:
        return JSONResponse({"detail": "profile_access_denied"}, status_code=403)
    request.state.profile_access = allowed
    host_level = request.url.path.startswith(_HOST_LEVEL_PATHS)
    if host_level:  # already checked above; dropped so the plugin runs on the launch profile's copy
        query = parse_qsl(request.scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
        request.scope["query_string"] = urlencode([(k, v) for k, v in query if k != "profile"]).encode("latin-1")
    with request_scope(allowed, bind_home=not host_level):
        return await call_next(request)


# ---- WebSockets: the scope rides the server-minted identity (ticket ``extra`` / token leg) ----

def ws_allowed(ws: Any) -> Optional[tuple[str, ...]]:
    """The profile scope stamped on *ws* at upgrade auth, or ``None`` (unrestricted)."""
    access = (getattr(ws, "_hermes_auth_identity", None) or {}).get("profile_access")
    return None if access is None else tuple(access)


def ws_profile(ws: Any, requested: Optional[str]) -> Optional[str]:
    """The profile a ``?profile=`` socket (pty, console) runs: *requested* when allowed, the user's
    default when it names none. Raises ``PermissionError`` past the scope."""
    allowed = ws_allowed(ws)
    if allowed is None:
        return requested
    if not allowed:
        raise PermissionError("profile_access_denied")
    if requested is None or requested.strip().lower() in {"", "current"}:
        return allowed[0]
    _check(requested, allowed, implicit_ok=False)
    return requested
