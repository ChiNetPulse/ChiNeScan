#!/usr/bin/env bash
set -Eeuo pipefail

# Run on the Oracle VM as an administrator after reviewing the templates.
# This script never creates a database schema and never enables scanner
# execution. It only installs the ordinary API service and proxy configuration.

APP_ROOT="${APP_ROOT:-/opt/chinescan}"
SERVICE_FILE="${SERVICE_FILE:-$APP_ROOT/deploy/oracle/chinescan.service}"
NGINX_FILE="${NGINX_FILE:-$APP_ROOT/deploy/oracle/nginx-chinescan.conf.template}"
ENV_FILE="${ENV_FILE:-/etc/chinescan/chinescan.env}"

if [[ "$(id -u)" != "0" ]]; then
  echo "bootstrap must run as root (use sudo after reviewing the command)" >&2
  exit 2
fi
if [[ ! -x "$APP_ROOT/.venv/bin/chinescan" ]]; then
  echo "missing locked application environment: $APP_ROOT/.venv/bin/chinescan" >&2
  exit 2
fi
if [[ ! -f "$SERVICE_FILE" || ! -f "$NGINX_FILE" ]]; then
  echo "missing Oracle deployment template under $APP_ROOT/deploy/oracle" >&2
  exit 2
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing protected environment file: $ENV_FILE" >&2
  exit 2
fi
if grep -Eq 'REPLACE_ME|REPLACE_SUPABASE_HOST|example\.com' "$ENV_FILE"; then
  echo "environment file still contains template placeholders" >&2
  exit 2
fi
if grep -Eq 'example\.com|REPLACE_' "$NGINX_FILE"; then
  echo "nginx configuration still contains template placeholders" >&2
  exit 2
fi
if ! getent passwd chinescan >/dev/null || ! getent group chinescan >/dev/null; then
  echo "required unprivileged chinescan user/group is missing" >&2
  exit 2
fi

install -d -o chinescan -g chinescan -m 0750 /var/lib/chinescan /etc/chinescan
chown root:chinescan "$ENV_FILE"
chmod 0640 "$ENV_FILE"
install -o root -g root -m 0644 "$SERVICE_FILE" /etc/systemd/system/chinescan.service

if command -v nginx >/dev/null 2>&1; then
  install -o root -g root -m 0644 "$NGINX_FILE" /etc/nginx/sites-available/chinescan.conf
  ln -sfn /etc/nginx/sites-available/chinescan.conf /etc/nginx/sites-enabled/chinescan.conf
  nginx -t
else
  echo "nginx is not installed; install/configure the approved TLS proxy before public exposure" >&2
  exit 2
fi

systemctl daemon-reload
systemctl enable chinescan.service
systemctl restart chinescan.service
curl --fail --silent --show-error --max-time 10 http://127.0.0.1:8765/api/health >/dev/null
systemctl is-active --quiet chinescan.service
echo "ordinary ChineScan backend is active on loopback; scanner execution remains policy-gated"
