# TRINET fork of Hermes Agent

Branch `feat/keycloak-profile-scope`, based on upstream tag `v0.23.2`. It adds one feature:
**a Keycloak (self-hosted OIDC) dashboard sign-in sees and uses only the profiles its groups map to.**

## Configure

In `config.yaml` (the Helm chart's `config.values`):

```yaml
dashboard:
  oauth:
    profile_access:
      admin_groups: [hermes-admin]   # see and manage every profile
      groups:                        # Keycloak group -> profiles; the first listed is the user's default
        marketing-writers: [penulis]
```

- No `profile_access` block: upstream behaviour, every signed-in user sees every profile.
- A user in no listed group (and not admin) gets no profile: every gated `/api/` call except sign-in and status is refused.
- An unreadable `config.yaml` fails closed: every Keycloak sign-in, admins included, gets no profile.
- The policy is always read from the launch profile's `config.yaml`, never a profile's own.
- The `groups` claim must be in the **ID token**: in Keycloak, add a "Group Membership" mapper to the
  client with "Add to ID token" on. Full group paths (`/name`) are accepted.

## What it scopes

| Surface | Behaviour for a scoped user |
|---|---|
| REST `?profile=` / body `profile` / `/api/profiles/{name}` | other profiles → 403 |
| Requests that name no profile | run in the user's default profile |
| Profile, status, cron and session listings | only the user's profiles |
| First page load (`__HERMES_INITIAL_PROFILE__`) | opens on the user's default profile |
| `/api/plugins/*`, `GET /api/dashboard/plugins` | run on the launch profile's plugin copy; the plugin scopes itself with `isolated_scope.request_profiles()` |
| Installing, hiding or updating plugins | admin only |
| Create / rename / delete / import profiles, set the sticky active profile | admin only |
| `/api/pty` (Chat tab), `/api/console` | open only the user's profiles (close 4403) |
| `/api/ws` (gateway JSON-RPC) | explicit other profile → refused; else the default profile |

**This is dashboard scoping, not isolation.** Profiles share one OS user, so the chat's agent,
its terminal tool or the console can still read other profiles' files. Isolation needs separate
containers or OS users.

## Code

All logic is in `hermes_cli/dashboard_auth/profile_access.py`; upstream files carry small hooks
marked `TRINET fork`. Tests: `tests/hermes_cli/test_trinet_profile_access.py`.

## Rebase onto a new upstream release

```sh
git fetch upstream --tags
git rebase --onto vX.Y.Z v0.23.2 feat/keycloak-profile-scope
.venv/bin/python -m pytest tests/hermes_cli/test_trinet_profile_access.py -q
```

Then bump `BASE_TAG` in `docker/trinet/Dockerfile` and check its COPY list against
`git diff --name-only vX.Y.Z -- ':!tests' ':!docker' ':!TRINET.md'`.

## Image

`docker/trinet/Dockerfile` layers the patched files over `nousresearch/hermes-agent:<BASE_TAG>`
(Python only, so it works for any architecture). Push as
`harbor.192.168.0.113.nip.io/hermes/hermes-agent:<BASE_TAG>-trinet.<n>`.
