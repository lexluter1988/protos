# Architecture

The maintained architecture document is now [`docs/arch.md`](./arch.md).

This file is kept as a short compatibility pointer for older links.

## Overview

The codebase now has three relay modes:

1. **MTProxy mode**: the primary Telegram-facing path
2. **Direct SOCKS5 mode**: fallback / diagnostics path
3. **Tunnel mode**: the legacy compatibility path for `tg_local`

Current priority:

```text
Telegram Client
    |
    | MTProxy secret-based transport
    v
tg_relay (public VPS)
    |
    | outbound obfuscated MTProto transport
    v
Telegram DC endpoint
```

Optional legacy path:

```text
Telegram Client
    |
    | SOCKS5
    v
tg_local
    |
    | TLS tunnel + shared token
    v
tg_relay (mode = "tunnel")
    |
    | outbound TCP
    v
Telegram endpoint
```

## MTProxy Mode

`tg_relay` in `mode = "mtproxy"`:

- listens publicly, typically on `:443`
- accepts MTProxy-compatible client connections using a configured secret
- supports plain 16-byte secrets, `dd`-prefixed padded mode, and `ee` fake-TLS mode
- extracts the requested Telegram DC from the client handshake
- maps that DC to a configured outbound Telegram endpoint
- opens a fresh outbound obfuscated MTProto transport to that endpoint
- relays transformed transport bytes bidirectionally with connect and idle timeouts

This is now the preferred direct mode for phones, laptops, and desktops.

## Direct SOCKS5 Mode

`tg_relay` in `mode = "direct_socks5"` remains available:

- for fallback use
- for diagnostics and smoke testing
- for non-Telegram tooling

## Legacy Tunnel Mode

`tg_relay` in `mode = "tunnel"` preserves the original two-part design:

- `tg_local` accepts loopback SOCKS5 connections
- `tg_local` creates one TLS connection per SOCKS5 `CONNECT`
- a shared token authenticates the tunnel request
- the relay resolves and connects the target
- bytes are streamed until EOF, timeout, or error

This mode remains useful where a desktop-local bridge is still desirable, but it is no longer the primary product direction.

## DPI-Relevant Notes

This refactor moves the product toward the right operational shape for blocked networks:

- direct remote MTProxy-compatible service instead of requiring a desktop-only helper
- standard public port usage such as `443`
- secret-based Telegram client configuration instead of an open relay
- endpoint rotation and secret rotation as operational tools

Current MTProxy scope:

- obfuscated secret-based transport is implemented
- `ee` fake-TLS ingress is implemented as a client-facing TLS-record wrapper over padded MTProxy transport
- outbound DC mapping is operator-configured

## Safety Controls

- MTProxy secret is required in MTProxy mode
- SOCKS5 auth is required in direct SOCKS5 mode
- private and loopback targets are denied by default in direct mode
- destination allowlists can be configured
- handshake timeout, connect timeout, and idle timeout are enforced
- connection counters are logged via `tracing`
- malformed client input is handled without crashing the process
