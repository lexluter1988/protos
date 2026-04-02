#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${1:-config/local.example.toml}"

cargo run -p tg_local -- --config "${CONFIG_PATH}"
