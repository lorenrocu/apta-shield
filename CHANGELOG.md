# Changelog

All notable changes to **Apta Shield** are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2] - 2026-06-22

### Fixed
- **Scanner False Positives**: Ignored core files that match official WordPress checksums. Modified heuristic signatures (removed false positives on active_plugins and string indexed table, restricted uploads directory check).
- **Url Obfuscator**: Fixed redirection loop/error by redirecting to a front-end route instead of trying to load templates during premature hooks.
- **Admin UI**: Main dashboard status indicator now correctly reflects if there are unresolved threat findings, and updates dynamically during manual scans.

## [1.1.1] - 2026-06-19

### Added
- **Onboarding Setup Wizard**: Step-by-step guidance for new users.

### Changed
- **Visual Redesign**: Updated admin dashboard tabs and visual styling.

### Fixed
- **Url Obfuscator Warnings**: Resolved login warning bugs.
- **Plugin Compliance**: Met standard WordPress.org plugin directory compliance requirements.

## [1.1.0] - 2026-06-17

### Security

- **Added `AptaShield\Common\IpResolver`**: new centralized class for
  resolving the real client IP. Walks the `X-Forwarded-For` chain from
  right to left and only honors it when the TCP peer (`REMOTE_ADDR`) is a
  configured trusted proxy. **Without a trusted proxy configured, XFF is
  completely ignored**, which is the safe default.
- **Removed spoofable IP resolution** from `Firewall`, `BruteForce`,
  `AuditLog`, `UrlObfuscator` and `Reinstaller`. All five modules now call
  `IpResolver::get_client_ip()`. The previous code took the leftmost entry
  of `X-Forwarded-For` with no validation, allowing any attacker to bypass
  IP-based bans by sending a forged header.
- **IPv4 and IPv6 support** in CIDR matching (Cloudflare, Sucuri, custom
  load balancers, etc.).
- **New admin setting**: `Proxies de Confianza (Anti-Spoofing de IP)` under
  the Hardening tab. Stores IPs and CIDR ranges (one per line). Invalid
  entries are silently dropped; duplicates are removed.

### Changed

- `Plugin::get_settings()` now includes a `trusted_proxies` key populated
  from the dedicated `apta_shield_trusted_proxies` WP option.
- `Dashboard::ajax_save_settings()` validates and persists the trusted
  proxy list on save.
- `views/tab-hardening.php` exposes the new setting with a textarea,
  inline help, and a list of common Cloudflare / Sucuri ranges.

### Added

- `tests/IpResolverTest.php` — standalone smoke test. Run with
  `php tests/IpResolverTest.php` from the project root. No WordPress
  required. Covers validation, CIDR matching, and 6 anti-spoofing
  scenarios including a full Cloudflare-chain test.

### Backward compatibility

- All five modules still expose their private `get_user_ip()` method as a
  thin wrapper around `IpResolver::get_client_ip()`. Any third-party
  code that reached into those classes (not recommended) keeps working
  but the methods are marked `@deprecated since 1.1.0`.

## [1.0.0] - initial release

- Firewall (WAF) with basic SQLi / XSS / LFI / RCE patterns.
- Brute force protection on `wp_login_failed` and `xmlrpc_login_error`.
- URL obfuscator with secret slug and IP-bound cookie.
- Malware and integrity scanner with daily cron.
- One-click WordPress core reinstaller.
- Audit log for sessions, content, plugins, users and tracked options.
- Hardening module: HTTP headers, XML-RPC, file edit, author scan, WP
  version hiding.
- Email notifier with HTML templates.
- Single-page admin dashboard with 7 tabs.
