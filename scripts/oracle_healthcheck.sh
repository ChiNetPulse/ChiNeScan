#!/usr/bin/env bash
set -Eeuo pipefail

BASE_URL="${1:-https://api.example.com}"
BASE_URL="${BASE_URL%/}"

health="$(curl --fail --silent --show-error --max-time 15 "$BASE_URL/api/health")"
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value.get("status") == "ok"' <<<"$health"
echo "health: ok"

ready_status="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 15 "$BASE_URL/api/ready")"
if [[ "$ready_status" == "401" || "$ready_status" == "403" ]]; then
  echo "readiness: protected ($ready_status); authenticated operator check required"
elif [[ "$ready_status" == "200" ]]; then
  echo "readiness: ok"
else
  echo "readiness: unexpected HTTP $ready_status" >&2
  exit 1
fi
