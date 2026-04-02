# Desktop Client Setup

The current primary deployment model is to point Telegram Desktop directly at `tg_relay` in MTProxy mode.

## Required Relay Settings

- `mode = "mtproxy"`
- a public `listen_addr`, typically on port `443`
- `[mtproxy].secret` configured
- recommended: `backend = "official"`
- if you use the pure-Rust fallback instead: `[[mtproxy.dc_endpoints]]` configured

## Telegram Desktop

1. Open `Settings`
2. Open `Advanced`
3. Open `Connection type`
4. Enable `Use custom proxy`
5. Select `MTProto` or `MTPROTO`
6. Set host to your VPS IP or domain
7. Set port to the relay listen port
8. Set secret from `[mtproxy].secret`

## Validation

- open a chat list and wait for initial sync
- send a test message
- open a media-heavy chat
- verify relay logs show successful authenticated connections

## If Desktop Connectivity Is Unstable

- move the relay to another port such as `443`
- rotate the MTProxy secret
- deploy a new VPS endpoint and test again
- if you are still using direct SOCKS5 fallback mode, switch to MTProxy mode instead
