#!/usr/bin/env bash
set -euo pipefail

CONFIG_OUT="${1:-var/telegram/proxy-multi.conf}"
SECRET_OUT="${2:-var/telegram/proxy-secret}"

cargo run -p tg_relay -- fetch-telegram-config --output "${CONFIG_OUT}" --secret-out "${SECRET_OUT}"
