#!/usr/bin/env bash
set -euo pipefail

SOCKS_ADDR="${SOCKS_ADDR:-127.0.0.1:443}"
SOCKS_USERNAME="${SOCKS_USERNAME:-}"
SOCKS_PASSWORD="${SOCKS_PASSWORD:-}"
TCP_TEST_HOST="${TCP_TEST_HOST:-api.telegram.org}"
TCP_TEST_PORT="${TCP_TEST_PORT:-443}"
LOCAL_DNS_URL="${LOCAL_DNS_URL:-https://api.telegram.org}"
REMOTE_DNS_URL="${REMOTE_DNS_URL:-https://api.telegram.org}"

if [[ -n "${SOCKS_USERNAME}" || -n "${SOCKS_PASSWORD}" ]]; then
  if [[ -z "${SOCKS_USERNAME}" || -z "${SOCKS_PASSWORD}" ]]; then
    echo "Set both SOCKS_USERNAME and SOCKS_PASSWORD or neither"
    exit 1
  fi
  PROXY_AUTH="${SOCKS_USERNAME}:${SOCKS_PASSWORD}@"
else
  PROXY_AUTH=""
fi

LOCAL_PROXY_URL="socks5://${PROXY_AUTH}${SOCKS_ADDR}"
REMOTE_PROXY_URL="socks5h://${PROXY_AUTH}${SOCKS_ADDR}"

echo "Testing raw TCP connect via SOCKS5 to ${TCP_TEST_HOST}:${TCP_TEST_PORT}"
if command -v nc >/dev/null 2>&1 && [[ -z "${PROXY_AUTH}" ]]; then
  nc -z -v -X 5 -x "${SOCKS_ADDR}" "${TCP_TEST_HOST}" "${TCP_TEST_PORT}"
else
  echo "Skipping raw TCP test because nc is unavailable or proxy auth is enabled"
fi

echo "Testing HTTPS via local DNS mode with socks5://"
curl --fail --silent --show-error --proxy "${LOCAL_PROXY_URL}" "${LOCAL_DNS_URL}" >/dev/null

echo "Testing HTTPS via remote DNS mode with socks5h://"
curl --fail --silent --show-error --proxy "${REMOTE_PROXY_URL}" "${REMOTE_DNS_URL}" >/dev/null

echo "Smoke tests passed"
