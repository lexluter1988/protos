#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${1:-config/relay.example.toml}"

cargo run -p tg_relay -- --config "${CONFIG_PATH}"
