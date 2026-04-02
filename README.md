# Telegram Remote Access Relay

This workspace now defaults to a **remote-first** Telegram access design:

- `tg_relay`: the primary public-facing service, now supporting a direct MTProxy-compatible frontend as well as authenticated SOCKS5
- `tg_local`: an optional legacy helper that still bridges a local SOCKS5 listener to the relay over a TLS tunnel

The immediate goal is practical deployment for blocked networks: run a server on a VPS, bind it on a commonly allowed port such as `443`, and point Telegram Desktop / Android / iOS clients at that server directly using MTProxy-compatible settings.

## Current Implementation

- Official MTProxy backend mode in `tg_relay`, with process supervision for Telegram's upstream `mtproto-proxy`
- Automatic fetch and refresh of `getProxyConfig` and `getProxySecret` in official backend mode
- Direct MTProxy-compatible Rust ingress retained as a `static_dc` fallback backend
- Supported MTProxy secret styles: plain 16-byte, `dd` padded mode, and `ee` fake-TLS mode
- Direct SOCKS5 mode retained as a fallback
- Username/password auth required for direct SOCKS5 mode
- Private and loopback destination blocking by default to reduce abuse
- Optional destination allowlists
- Legacy tunnel mode retained for `tg_local`
- Docker and systemd deployment artifacts
- End-to-end tests for MTProxy mode, direct SOCKS5 mode, and legacy tunnel mode

## Important Boundary

Recommended MTProxy deployment now uses Telegram's official backend routing live, but it does so by supervising the external upstream `mtproto-proxy` binary.

See the fuller architecture note in [docs/arch.md](docs/arch.md).

The repo still includes a manual fetcher for Telegram’s official MTProxy artifacts:

```bash
./scripts/fetch_telegram_config.sh
```

That downloads `getProxyConfig` and `getProxySecret` into `var/telegram/`, validates them, and caches them locally. In `backend = "official"` the running relay now uses the same artifact flow automatically.

## Quick Start

1. Edit [`config/relay.example.toml`](config/relay.example.toml).
2. Set a real `listen_addr`, MTProxy `secret`, and `mtproxy.official.binary_path`.
3. For `ee` fake-TLS mode, keep `mtproxy.official.workers = 0`.
4. Start the relay:

   ```bash
   ./scripts/run_relay.sh config/relay.example.toml
   ```

5. Configure Telegram to use the relay directly:
   - Proxy type: `MTProto` / `MTProxy`
   - Host: your VPS IP or domain
   - Port: the relay listen port, typically `443`
   - Secret: the configured MTProxy secret

6. If you want the older pure-Rust MTProxy backend instead of the official one, switch to `backend = "static_dc"` and populate `[[mtproxy.dc_endpoints]]`.

7. If you want a SOCKS5 fallback instead, switch the relay config to `mode = "direct_socks5"` and use the SOCKS smoke check:

   ```bash
   SOCKS_ADDR=127.0.0.1:443 SOCKS_USERNAME=telegram SOCKS_PASSWORD=change-me ./scripts/smoke_test.sh
   ```

## Legacy Helper

If you still want the old local helper flow on a desktop, `tg_local` remains available. That path now counts as a secondary compatibility mode and requires the relay to run in `mode = "tunnel"`.

## Testing

```bash
cargo test --workspace
```

The current automated tests cover:

- tunnel protocol round trips
- legacy `tg_local -> tg_relay` tunnel forwarding
- direct MTProxy frontend relaying to a configured DC
- direct authenticated SOCKS5 relay mode
- default rejection of private destinations in direct mode

## Docs

- [Architecture](docs/arch.md)
- [Legacy Architecture Note](docs/architecture.md)
- [Deploy On Ubuntu](docs/deploy_ubuntu.md)
- [Desktop Client Setup](docs/client_setup_desktop.md)
- [Mobile Client Setup](docs/client_setup_mobile.md)
- [Operations](docs/operations.md)
- [Testing Guide](docs/testing.md)
- [Optional Local Helper](docs/local_run_mac.md)
