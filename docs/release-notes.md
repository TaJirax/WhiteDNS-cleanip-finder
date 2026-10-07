WhiteDNS v1.4.6: a redesigned, faster Android app, plus anti-DPI, speed tests and DNS rate limits.

## Android app

- **A new look**, matching the WhiteDNS Scanner desktop app: its colours, icons, light and dark themes, and accent colours. Forms are easier to scan and the progress bar shows real progress.
- **Faster everywhere.**
  - The app starts about three times faster.
  - The APK is much smaller: 9 MB for arm64, down from 32 MB.
  - ASN search answers each keystroke about 20 times faster.
  - Exporting ASN IPs is about 5 times faster.
- **Saved results:** reopen past scans from the home screen, and search inside results.
- **"Cloudflare all (13)" port preset:** scan every Cloudflare HTTPS and HTTP port in one go.
- **Speed test through a found IP:** measure download speed through the endpoint itself.
- **Anti-DPI:** optional ClientHello fragmentation for IP and proxy scans.
- **DNS rate limit:** an optional query rate, per resolver or overall, with timing jitter, for networks that drop DNS above a fixed rate.
- Works better on large screens and in landscape, keyboard handling is fixed, and changing the font size no longer resets your place.

## Scanning engine (Android and terminal)

- **Overlapping ranges are scanned once.** ASN exports and scans merge overlapping ranges, so every IP appears exactly once. Tests check every one of the 159.6 million IPv4 addresses in the bundled ASN data.
- **The ASN tables are built in;** no data files are needed.
- Domain targets are supported in IP scans.
