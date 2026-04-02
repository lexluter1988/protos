# Deploy On Ubuntu

## 1. Prepare The Host

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config ca-certificates git curl libssl-dev zlib1g-dev
```

For a public endpoint, prefer a commonly allowed port such as `443`.

## 2. Configure The Relay

Start from [`config/relay.example.toml`](../config/relay.example.toml).

For the current remote-first implementation:

- set `mode = "mtproxy"`
- bind `listen_addr` to your public port, typically `0.0.0.0:443`
- set `[mtproxy].secret`
- prefer `backend = "official"`
- set `[mtproxy.official].binary_path` to the built upstream `mtproto-proxy`
- for `ee` fake-TLS mode, keep `[mtproxy.official].workers = 0`
- keep private destinations blocked unless you are explicitly using direct SOCKS5 fallback mode

If you want the pure-Rust fallback backend instead, switch to `backend = "static_dc"` and populate `[[mtproxy.dc_endpoints]]`.

## 3. Build The Official MTProxy Backend

```bash
git clone --depth 1 https://github.com/TelegramMessenger/MTProxy /opt/MTProxy
cd /opt/MTProxy
make
```

The resulting binary is typically:

```bash
/opt/MTProxy/objs/bin/mtproto-proxy
```

## 4. Build tg_relay

```bash
cargo build --release -p tg_relay
```

## 5. Run

Optional helper for the Telegram-managed artifacts:

```bash
./scripts/fetch_telegram_config.sh
```

Then start the relay:

```bash
./scripts/run_relay.sh config/relay.example.toml
```

Or directly:

```bash
./target/release/tg_relay --config config/relay.example.toml
```

In `backend = "official"`, `tg_relay` will fetch and refresh `getProxyConfig` and `getProxySecret` automatically by default.

## 6. Docker

```bash
docker compose up --build -d
```

The image builds `tg_relay` and also bakes in the upstream `mtproto-proxy` binary at `/opt/MTProxy/objs/bin/mtproto-proxy`. The compose file mounts the config under `/etc/tg-relay/config.toml` and persists Telegram artifact cache under `./var/telegram`.

## 7. systemd

```bash
sudo cp target/release/tg_relay /usr/local/bin/tg_relay
sudo cp systemd/tg-relay.service /etc/systemd/system/tg-relay.service
sudo mkdir -p /var/lib/tg-relay/var/telegram
sudo chown -R tgproxy:tgproxy /var/lib/tg-relay
sudo systemctl daemon-reload
sudo systemctl enable --now tg-relay.service
```

Inspect logs:

```bash
journalctl -u tg-relay -f
```

## 8. Firewall

- Allow inbound TCP only on the relay port.
- Restrict SSH separately.
- Do not run direct SOCKS5 mode without SOCKS auth.
- Rotate the MTProxy secret and public endpoint if the endpoint becomes unreliable or obviously blocked.
