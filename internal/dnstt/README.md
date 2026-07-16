# internal/dnstt — vendored dnstt client (DNS tunnel)

This package vendors the **client** half of David Fifield's `dnstt` DNS tunnel
and adapts it into a single `Dial` call used by the end-to-end resolver
validator (`internal/e2e`).

- Upstream: <https://www.bamsoftware.com/software/dnstt/> (public domain).
- Vendored verbatim: `dns/`, `noise/`, `turbotunnel/` (plus upstream's own
  `dns_test.go` / `noise_test.go`, kept to prove the copies are intact).
- Adapted here:
  - `dnspacketconn.go` — from `dnstt-client/dns.go` (the DNS-over-UDP packet
    transport). Upstream's per-packet `log.Printf` calls are removed because
    this runs once per resolver inside a bulk scanner.
  - `dial.go` — from `dnstt-client/main.go`'s `run()`, reshaped into
    `Dial(ctx, resolver, domain, pubkey, transport) (net.Conn, error)` that
    returns one smux stream and tears the whole tunnel down on `Close`.
  - `backend.go` — adapter exposing `NewValidator()` for `internal/e2e`.

## Scope / deliberate limitations

- **UDP transport only.** DoH/DoT (`dnstt-client/{http,tls,utls}.go`) are *not*
  vendored: they pull in uTLS + brotli + circl, which would bloat the Android
  `.aar` and are unnecessary for validating a plain UDP/53 resolver. `Dial`
  rejects any transport other than `""`/`"udp"`.
- Pure Go (deps: `flynn/noise`, `xtaci/kcp-go/v5`, `xtaci/smux`,
  `golang.org/x/crypto`), so it stays gomobile-safe.

## Updating

Re-copy `dns/`, `noise/`, `turbotunnel/` from an upstream checkout (no import
paths to rewrite — they don't cross-import the vanity module path), then
re-apply the log-stripping in `dnspacketconn.go` and re-check `dial.go` against
upstream `run()`.
