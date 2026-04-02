# Testing Guide

## Automated Tests

```bash
cargo test --workspace
```

Current automated coverage:

- tunnel protocol encode/decode round trips
- legacy `tg_local -> tg_relay` forwarding in tunnel mode
- direct MTProxy frontend relaying to a configured DC endpoint
- direct authenticated SOCKS5 relay mode
- default rejection of private targets in direct mode

## Smoke Test Script

The smoke script targets the SOCKS5 fallback mode and supports optional auth. MTProxy mode is currently validated through integration tests and manual Telegram client checks.

Example against a local relay on port `443`:

```bash
SOCKS_ADDR=127.0.0.1:443 SOCKS_USERNAME=telegram SOCKS_PASSWORD=change-me ./scripts/smoke_test.sh
```

Useful environment variables:

- `SOCKS_ADDR=127.0.0.1:443`
- `SOCKS_USERNAME=telegram`
- `SOCKS_PASSWORD=change-me`
- `TCP_TEST_HOST=api.telegram.org`
- `TCP_TEST_PORT=443`
- `LOCAL_DNS_URL=https://api.telegram.org`
- `REMOTE_DNS_URL=https://api.telegram.org`

The script performs:

- raw TCP `CONNECT` via `nc` when auth is not required and `nc` supports SOCKS5 proxying
- HTTPS request through `socks5://`
- HTTPS request through `socks5h://`

## Manual Desktop Validation

1. Start `tg_relay` on the VPS.
2. Configure Telegram Desktop to use the relay directly as an MTProto proxy.
3. Enter the configured MTProxy secret.
4. Confirm the client connects without repeated reconnect loops.
5. Send and receive a test message.
6. Open media-heavy chats to exercise longer-lived connections.
7. Check relay logs for auth failures, rejected destinations, and connect failures.

## Manual Mobile Validation

1. Start `tg_relay` on the VPS.
2. Configure the mobile Telegram client with the server host, port, and MTProxy secret.
3. Confirm the app connects and stays connected when switching networks.
4. Re-test after rotating credentials or changing the listen port.

## Failure Modes To Check

- wrong MTProxy secret
- relay port blocked or throttled
- public endpoint reachable but Telegram still unstable under local censorship conditions
- idle timeout too short for the network path
- incorrect Telegram DC mapping in `mtproxy.dc_endpoints` when using `backend = "static_dc"`
