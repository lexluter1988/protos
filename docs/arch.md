# Architecture

## Goal

The system is optimized for one job:

- Telegram remains usable from blocked or DPI-shaped Russian networks.

That drives three product choices:

- the deployment is remote-first
- Telegram clients connect directly to the public server
- MTProxy is the primary transport, with SOCKS5 kept only as a fallback

## System Shape

Recommended path:

```text
Telegram Client
    |
    | MTProxy / MTProto proxy settings
    v
tg_relay
    |
    | supervises official mtproto-proxy
    | auto-refreshes getProxyConfig + getProxySecret
    v
Telegram official middle-proxy backend
    |
    v
Telegram network
```

Fallback custom path:

```text
Telegram Client
    |
    | MTProxy / MTProto proxy settings
    v
tg_relay
    |
    | Rust MTProxy ingress + direct obfuscated MTProto egress
    v
Operator-configured Telegram DC endpoint
```

Legacy helper path:

```text
Telegram Client
    |
    | SOCKS5
    v
tg_local
    |
    | TLS tunnel + token
    v
tg_relay (mode = "tunnel")
```

## Relay Modes

### `mode = "mtproxy"`

This is the primary mode.

Within MTProxy mode there are now two backend strategies.

#### `backend = "official"`

This is the recommended production path.

`tg_relay` does not terminate MTProxy traffic itself in this mode. Instead it:

- validates config
- derives the right upstream `mtproto-proxy` flags from the configured client secret
- supervises Telegram's official `mtproto-proxy` binary
- fetches `getProxyConfig` and `getProxySecret`
- writes them atomically into local cache paths
- restarts the official backend after successful refreshes
- restarts the backend if the child exits unexpectedly

Important details:

- plain 16-byte secrets are supported
- `dd` secrets are supported by stripping the `dd` prefix before passing `-S` upstream
- `ee` secrets are supported by extracting the base 16-byte secret and passing the embedded domain as `-D`
- the official backend gets live Telegram-managed routing instead of static DC maps
- fake-TLS `ee` mode runs with `workers = 0` to avoid upstream prefork instability there

This is the only mode in the repo that actually uses Telegram-managed backend metadata for live traffic.

#### `backend = "static_dc"`

This is the existing pure-Rust path.

`tg_relay`:

- accepts MTProxy-compatible client connections directly
- supports plain, `dd`, and `ee` ingress secrets
- extracts the requested client DC from the MTProxy handshake
- maps that DC to configured `[[mtproxy.dc_endpoints]]`
- opens outbound obfuscated MTProto connections itself

This is useful for:

- tests
- controlled experiments
- situations where the official MTProxy binary is unavailable

It is not the recommended production path anymore because routing remains operator-maintained.

### `mode = "direct_socks5"`

This remains a fallback mode for:

- diagnostics
- smoke tests
- desktop fallback experiments

It is not the preferred anti-DPI path.

### `mode = "tunnel"`

This remains only for legacy `tg_local` support.

## Client-Facing MTProxy Behavior

Both MTProxy backend strategies support the same client-facing secret families:

- plain 16-byte MTProxy secret
- `dd` + 16-byte secret for padded transport
- `ee` + 16-byte secret + hex-encoded ASCII domain for fake-TLS mode

### Plain / `dd`

```text
Telegram Client
    -> MTProxy obfuscated handshake
    -> transport payload
```

### `ee` fake-TLS

```text
Telegram Client
    -> fake TLS ClientHello
    -> dummy ChangeCipherSpec
    -> TLS application-data records carrying MTProxy bytes
```

In `backend = "static_dc"`, Rust terminates that ingress framing itself.

In `backend = "official"`, `tg_relay` converts the configured secret into the upstream binary arguments and the official backend handles the live client traffic.

## Artifact Refresh

`tg_relay fetch-telegram-config` remains available as a manual fetch command.

In `backend = "official"`, the same artifact sources are now used at runtime:

- `https://core.telegram.org/getProxyConfig`
- `https://core.telegram.org/getProxySecret`

Operator flow:

1. `tg_relay` tries to fetch fresh artifacts at startup when `auto_refresh = true`
2. if that fails, it falls back to the cached local files
3. while running, it refreshes on the configured interval
4. after a successful refresh, it restarts the official backend so new routing takes effect

This gives automatic DC and backend discovery without manual `dc_endpoints` edits.

## Reliability Controls

- handshake, connect, and idle timeouts remain enforced in Rust-managed modes
- direct SOCKS5 mode still requires auth
- tunnel mode still requires TLS plus token auth
- official MTProxy mode validates the local artifact cache before starting from it
- official MTProxy mode restarts the child after crashes and after successful artifact refreshes

## Remaining Limitation

The remaining limitation is different now.

The repo can use Telegram-managed backend routing live, but the production-grade path depends on the external official `mtproto-proxy` binary.

So:

- live official backend routing is implemented
- automatic artifact refresh is implemented
- pure-Rust live official-backend compatibility is not implemented

That tradeoff is deliberate. The backend protocol behind `proxy-multi.conf` is not just a list of DC IPs, and pretending otherwise would be incorrect.

## Why This Is The Right Shape

For this project goal, correctness under Russian blocking matters more than purity.

Supervising the official MTProxy backend gives:

- Telegram-managed routing
- lower operator burden
- better alignment with Telegram's own MTProxy deployment model
- less guesswork than a homegrown reimplementation of the middle-proxy backend protocol

The pure-Rust `static_dc` backend remains available, but it is now clearly a fallback path rather than the primary one.
