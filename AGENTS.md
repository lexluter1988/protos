# AGENTS.md

## Project mission

Build a **Rust-based Telegram access system** whose primary goal is to **work through Russian DPI and blocking** so Telegram remains usable from censored networks.

The product must be **remote-first**:

- it runs on a cloud Linux server or VPS
- users can connect to it directly from **phones, laptops, and desktops**
- a local companion app is optional, not the core product

The primary success criterion is practical usability under real blocked-network conditions:

1. A remote server can be deployed on a VPS with minimal setup.
2. Telegram clients can be configured to use the remote service directly.
3. The solution remains usable when ordinary direct Telegram access is disrupted by Russian DPI or blocking.
4. The deployment is stable, observable, and easy to rotate or recover if a secret or endpoint is blocked.
5. The system is not an open unauthenticated public relay.

---

## Product direction

The goal is **not** to build a generic proxy for its own sake. The goal is:

**Telegram works reliably from censored Russian networks.**

This changes the product priorities:

- **DPI resistance matters more than architectural purity.**
- **Direct client usability from Telegram apps matters more than requiring a local helper.**
- **Transport camouflage / anti-fingerprinting is in scope.**
- We should **not artificially exclude MTProxy/MTProto-compatible approaches** if they work materially better than plain SOCKS5 for this use case.

### Client-facing protocol decision

Prefer protocols that Telegram clients already support natively across platforms.

Guidance:

- **MTProxy / MTProto-compatible mode is in scope and may be the primary mode** if it is more reliable against DPI.
- **SOCKS5 is also in scope**, especially for desktop usage, diagnostics, and fallback modes.
- Do **not** lock the product to a local-agent-only SOCKS5 architecture.
- The final protocol choice should be based on what works best for real Telegram connectivity under Russian blocking conditions.

### Chosen architecture

Implement a **remote-first system**:

- **Remote edge service** on a cloud Linux server:
  - exposed on a public address, typically `:443` or another configurable port
  - accepts authenticated client connections directly from Telegram clients where possible
  - forwards Telegram-related traffic or implements a Telegram-compatible proxy mode
  - includes the transport choices and handshake behavior needed to reduce DPI detectability
  - supports secret rotation, endpoint rotation, and operational diagnostics

- **Optional local helper** (`tg_local`), only if useful:
  - may expose a local SOCKS5 endpoint on desktop platforms
  - may bridge to the remote service
  - is a secondary capability, not the primary deployment model

This is the MVP:

- optimize for **real Telegram usability from Russia**
- optimize for **direct usage from phones and laptops**
- do **not** optimize for a generic unrestricted proxy product

---

## Scope

### In scope

- Rust workspace with:
  - `tg_relay` as the primary remote service
  - optional `tg_local` helper
  - optional shared crate `crates/common`
- Remote-first deployment on VPS / cloud Linux
- Direct client configuration from:
  - Telegram Desktop
  - Android Telegram clients
  - iOS Telegram clients, if protocol support allows
  - other laptops/desktops where Telegram supports the chosen proxy mode
- Protocol selection driven by real censorship-resistance results
- Traffic camouflage / transport shaping / handshake hardening needed for Russian DPI
- Authenticated access with per-user or shared secrets
- Config files / environment variables
- Docker deployment for relay
- systemd service example for relay
- Client setup documentation for desktop and mobile
- Integration tests and smoke tests
- Logging and basic metrics / diagnostics
- Safe defaults that avoid creating an open relay

### Out of scope for MVP

- Generic public open proxying for arbitrary unrelated traffic
- GUI management app
- Multi-hop routing
- Advanced distributed control plane
- Auto-update
- Kubernetes manifests
- UDP support unless the chosen Telegram-compatible mode requires it

If the MVP works reliably, then optional improvements can be considered.

---

## Hard requirements

### Language and stack

- Language: **Rust**
- Async runtime: **tokio**
- TLS: **rustls** where TLS is part of the design
- CLI parsing: `clap`
- Config format: `TOML` preferred
- Serialization: `serde`
- Logging: `tracing` + `tracing-subscriber`

### Platforms

- Primary server target:
  - Ubuntu 24.04
- Code should remain portable to generic Linux x86_64
- Client usability target:
  - macOS
  - Windows
  - Linux
  - Android
  - iOS, where Telegram client proxy support allows it
- Optional local helper may target:
  - macOS first
  - Linux and Windows second

### Network behavior

- The primary product must be usable as a **remote service** that Telegram clients can point to directly.
- Default public bind should favor standard ports commonly allowed by restrictive networks, especially `443`.
- The implementation must consider Russian DPI realities:
  - easy protocol fingerprinting is undesirable
  - obvious custom cleartext markers are undesirable
  - handshake behavior should be simple, robust, and hard to distinguish from expected traffic where practical
- Authentication must use secrets / tokens / keys appropriate to the chosen protocol
- If a generic relay mode exists, outbound traffic should be **restricted to Telegram-related destinations** or another clearly limited allowlist to avoid creating an abuse surface

### Reliability

- Must handle multiple concurrent clients
- Must not crash on malformed client input
- Must have bounded memory behavior
- Must implement sane timeouts:
  - handshake timeout
  - connect timeout
  - idle timeout
- Must close dead connections cleanly
- Must log errors with actionable messages
- Must support practical operator recovery actions:
  - rotating secrets
  - changing listen ports
  - updating certs or camouflage settings

---

## Functional requirements

## 1. Remote service (`tg_relay`)

This is the primary product.

Responsibilities:

- Listen on a configurable public address, typically `0.0.0.0:443`
- Accept authenticated client connections from Telegram clients directly, if the chosen proxy mode supports it
- Or accept authenticated connections from an optional local helper when direct client use is not sufficient
- Implement the chosen Telegram-usable proxy mode:
  - MTProxy / MTProto-compatible mode if needed
  - SOCKS5 only when it is practically effective
- Apply anti-DPI design choices appropriate for the protocol:
  - reduce obvious fingerprinting
  - avoid needlessly distinctive wire behavior
  - allow operational rotation when blocked
- Open and relay only the traffic necessary for Telegram connectivity
- Enforce limits:
  - max concurrent clients
  - handshake / request size limits where applicable
  - request validation
  - timeouts
  - authentication failures

Configuration parameters should include:

- listen address / port
- protocol mode
- auth secret(s)
- TLS cert path / key path when TLS is used
- outbound connect timeout
- idle timeout
- max concurrent clients
- logging level
- Telegram endpoint allowlist or routing policy
- optional camouflage / transport settings if used

Security notes:

- Reject unauthenticated requests
- Do not expose an open public unauthenticated relay
- Restrict or validate destinations where relevant
- Avoid panics on bad input
- Avoid unsafe Rust unless absolutely necessary

## 2. Optional local helper (`tg_local`)

This is secondary and should exist only if it materially improves usability for some environments.

Responsibilities, if implemented:

- Listen on a configurable local address, for example `127.0.0.1:1080`
- Expose a client-friendly local interface such as SOCKS5
- Forward traffic to the remote service
- Be useful for desktop environments where a local bridge is easier than direct remote configuration

Configuration parameters may include:

- local listen address
- remote relay address
- server name for TLS verification if applicable
- auth secret
- connect timeout
- idle timeout
- DNS mode if SOCKS5 is used
- logging level

Behavior notes:

- `tg_local` must never become the only supported way to use the product
- Mobile usability must not depend on a local helper

---

## Protocol guidance

Choose the protocol and transport based on what is most likely to keep Telegram usable under Russian DPI.

Principles:

- Prefer **native Telegram client compatibility**
- Prefer **remote direct usability**
- Prefer **simple, versioned, bounded parsing**
- Prefer **operationally rotatable secrets and endpoints**
- Avoid inventing a complex custom protocol unless it is clearly necessary

If a custom tunnel is still used anywhere:

- make it binary and versioned
- bound maximum handshake size
- fail closed on bad frames
- avoid obvious static markers that make DPI identification trivial

Do not keep the old local-agent tunnel architecture as a goal in itself if a direct remote protocol works better.

---

## Telegram-specific success criteria

The implementation is successful only if **Telegram actually works from censored Russian networks**.

### Mandatory success criteria

1. The remote service starts on an Ubuntu VPS.
2. At least one Telegram desktop client can be configured to use it directly and function.
3. At least one mobile Telegram client path is documented and targeted if the chosen protocol supports it.
4. The solution is meaningfully more usable than a plain direct connection when Russian DPI / blocking interferes with Telegram.
5. Operators can rotate secrets and redeploy without redesigning the system.

### Connectivity and validation tests to support

At minimum, document and automate:

- service startup and configuration validation
- TCP reachability of the public server endpoint
- Telegram-related connectivity checks through the configured proxy mode
- endpoint or secret rotation procedure
- real Telegram client manual validation checklist on desktop
- mobile client validation checklist where applicable

Do not hardcode fragile endpoint assumptions unless they are configurable.

---

## Deliverables

Codex must produce:

1. **Rust workspace** with:
   - `crates/tg_relay`
   - optional `crates/tg_local`
   - optional shared crate `crates/common`

2. **Docs**
   - `README.md`
   - `docs/architecture.md`
   - `docs/deploy_ubuntu.md`
   - `docs/client_setup_desktop.md`
   - `docs/client_setup_mobile.md`
   - optional `docs/local_run_mac.md` if `tg_local` remains
   - `docs/testing.md`
   - `docs/operations.md`

3. **Config examples**
   - `config/relay.example.toml`
   - optional `config/local.example.toml`

4. **Deployment artifacts**
   - `Dockerfile` for relay
   - `docker-compose.yml` for relay
   - `systemd/tg-relay.service`

5. **Test artifacts**
   - unit tests
   - integration tests
   - smoke test script(s)
   - manual Telegram validation checklist(s)

6. **Operational scripts**
   - certificate / secret generation examples where relevant
   - relay launch script
   - optional local launch script
   - secret rotation or deployment helper scripts if needed

---

## Directory layout

Recommended layout:

```text
.
├── Cargo.toml
├── Cargo.lock
├── README.md
├── AGENTS.md
├── config/
│   ├── relay.example.toml
│   └── local.example.toml            # optional
├── crates/
│   ├── common/
│   ├── tg_local/                     # optional
│   └── tg_relay/
├── docs/
│   ├── architecture.md
│   ├── deploy_ubuntu.md
│   ├── client_setup_desktop.md
│   ├── client_setup_mobile.md
│   ├── local_run_mac.md              # optional
│   ├── testing.md
│   └── operations.md
├── scripts/
│   ├── dev_cert.sh                   # if relevant
│   ├── run_local.sh                  # optional
│   ├── run_relay.sh
│   └── smoke_test.sh
├── systemd/
│   └── tg-relay.service
└── docker/
    └── docker-compose.yml
```
