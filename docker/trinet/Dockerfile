# TRINET overlay: upstream's published image plus the fork's patched Python files (TRINET.md).
# BASE_TAG must be the upstream tag this branch is based on, or these files replace newer code.
ARG BASE_TAG=v0.23.2
FROM nousresearch/hermes-agent:${BASE_TAG}

COPY hermes_cli/dashboard_auth/base.py hermes_cli/dashboard_auth/profile_access.py \
     hermes_cli/dashboard_auth/routes.py /opt/hermes/hermes_cli/dashboard_auth/
COPY hermes_cli/isolated_scope.py hermes_cli/web_server.py hermes_cli/web_server_chat.py \
     hermes_cli/web_server_cron.py hermes_cli/web_server_dashboard.py /opt/hermes/hermes_cli/
COPY hermes_cli/web_routers/chat_ws.py hermes_cli/web_routers/dashboard_ui.py hermes_cli/web_routers/profiles.py \
     /opt/hermes/hermes_cli/web_routers/
COPY plugins/dashboard_auth/self_hosted/__init__.py /opt/hermes/plugins/dashboard_auth/self_hosted/
COPY tui_gateway/ws.py tui_gateway/ws_legacy_fallback.py /opt/hermes/tui_gateway/
