# Optional Local Helper On macOS

`tg_local` is now a secondary compatibility mode. Use it only if you explicitly want a local desktop bridge; the primary product flow is to point Telegram directly at `tg_relay`.

## When This Still Helps

- desktop-only workflows
- local app testing
- environments where you prefer a loopback proxy and a separate remote tunnel

## Important Requirement

The relay must run in:

```toml
mode = "tunnel"
```

The direct remote SOCKS5 mode is for clients to connect to the relay directly, not for `tg_local`.

## Steps

1. Generate a development certificate:

   ```bash
   ./scripts/dev_cert.sh
   ```

2. Configure [`config/local.example.toml`](../config/local.example.toml).
3. Configure the relay in `mode = "tunnel"` with matching TLS cert/key and `auth_token`.
4. Start the relay.
5. Start the local helper:

   ```bash
   ./scripts/run_local.sh config/local.example.toml
   ```

6. Point Telegram Desktop at `127.0.0.1:1080`.

## Validation

```bash
SOCKS_ADDR=127.0.0.1:1080 ./scripts/smoke_test.sh
```

## Notes

- `tg_local` keeps the original TLS tunnel design intact.
- It is useful for compatibility, but it is no longer the primary path for phones or laptops in the updated project direction.
