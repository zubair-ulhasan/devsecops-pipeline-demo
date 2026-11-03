#!/usr/bin/env bash
# Waits for the target to answer on the given URL and checks that it returns HTTP 200.
# Usage: bash scripts/smoke-test.sh http://localhost:3000/health
set -euo pipefail

url="${1:?usage: smoke-test.sh <url>}"

for attempt in $(seq 1 20); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$url" || true)"
  if [ "$code" = "200" ]; then
    echo "OK: $url returned 200 (attempt $attempt)"
    exit 0
  fi
  echo "attempt $attempt: got '${code}', retrying in 1s"
  sleep 1
done

echo "FAIL: $url never returned 200"
exit 1
