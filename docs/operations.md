# Operations

## Baseline

- keep the relay on a standard allowed port such as `443`
- prefer `mode = "mtproxy"` for Telegram clients
- prefer `backend = "official"` for MTProxy unless you explicitly need the pure-Rust fallback
- watch logs for repeated auth failures and connect failures

## Rotation Playbook

If the endpoint becomes unreliable:

1. Rotate the MTProxy secret.
2. Change the public listen port if needed.
3. Move to a new VPS IP if the current endpoint appears to be blocked.
4. Re-test with desktop and mobile clients.

## Destination Policy

Direct mode blocks private and loopback targets by default. Optional allowlists can narrow the relay further:

- exact domains
- domain suffixes
- exact IPs

If Telegram connectivity breaks after tightening policy, loosen it carefully and test again.

## Official MTProxy Backend

Recommended MTProxy mode now supervises Telegram's upstream `mtproto-proxy` binary.

Operational notes:

- keep `mtproxy.official.binary_path` correct
- keep `proxy_config_path` and `proxy_secret_path` on persistent storage
- leave `auto_refresh = true` unless you want manual artifact control
- in `ee` fake-TLS mode, keep `workers = 0`
- expect the child MTProxy process to restart after successful Telegram artifact refreshes
- if you use fake-TLS `ee` secrets, make sure the embedded domain is the one you actually want to expose to clients

## Telegram Artifact Fetcher

The repo can now download Telegram's official MTProxy artifacts directly:

```bash
./scripts/fetch_telegram_config.sh
```

Or directly:

```bash
cargo run -p tg_relay -- fetch-telegram-config --output var/telegram/proxy-multi.conf --secret-out var/telegram/proxy-secret
```

In `backend = "official"` the running relay uses the same artifact sources automatically. The manual fetcher is still useful for inspection or pre-seeding cache files.

## Static DC Backend

If you intentionally run `backend = "static_dc"`:

- keep `dc_endpoints` current yourself
- include the DC ids your clients actually need
- if media traffic is unstable, add the corresponding negative DC ids as well

## Tunnel Mode Maintenance

If you still use `tg_local`:

- run the relay in `mode = "tunnel"`
- rotate `auth_token` when needed
- rotate TLS certs if you are using self-signed tunnel certificates

## Observability

The relay logs:

- accepted connections
- active connection counts
- success/failure counts
- auth and connect errors

Use `journalctl -u tg-relay -f` under systemd or container logs under Docker.
