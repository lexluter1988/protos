# Mobile Client Setup

The updated project goal is direct mobile usability. The preferred implemented path is MTProxy mode to `tg_relay`.

## Android

In Telegram for Android, configure an MTProto / MTProxy proxy with:

- server: your VPS IP or domain
- port: relay listen port
- secret: `[mtproxy].secret`

Then validate:

- initial connection succeeds
- messages send and receive
- the app reconnects after switching between Wi‑Fi and cellular

## iOS

If the Telegram iOS client version in use supports MTProto proxy configuration, use the same server, port, and secret values as above.

Then validate:

- the proxy saves successfully
- the client connects without repeated reconnect loops
- traffic remains usable after background/foreground transitions

## Practical Note

For hostile networks, prefer an `ee` fake-TLS MTProxy secret instead of a plain or `dd` secret. For production deployments, also prefer `backend = "official"` so the relay uses Telegram-managed backend routing instead of operator-maintained DC endpoint maps.
