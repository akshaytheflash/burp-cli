# burp-cli TODO

## Implemented

### Core
- [x] Rust 2021 crate `burp-cli` v1.0.0, library `burpcli` + binary `burpcli`
- [x] HTTP/1.1 core: request/response parsing, serialization, framing, chunked decoding
- [x] Blocking HTTP client: TLS (rustls/ring), redirects, cookies, proxy, timeouts, size caps
- [x] TLS options: insecure verifier + extra trust anchors
- [x] Cookie jar (RFC 6265 subset)
- [x] Utilities: base64/hex/URL helpers, globs, table output, colors, durations, file locks
- [x] Global + per-project config (TOML), atomic writes
- [x] Scope matching (include/exclude, wildcards)
- [x] Project storage: history JSONL, issues JSONL, sitemap JSON, session JSON
- [x] Session handling: cookies, static headers, match/replace rules, login macros

### Tooling
- [x] Sitemap tree/list/show/add/import/remove/clear
- [x] Comparer: line/word/byte diff, similarity, context, JSON output
- [x] Decoder: base64/url/hex/html/gzip/deflate/rot13/binary/hashes, JWT decode/sign/none, smart decode, identification
- [x] Sequencer: entropy, chi-square, monobit, runs, serial correlation, position entropy, sequential detection
- [x] Intruder engine: §...§ markers, multiple attack modes, payload sources
      (list/file/numbers/hex/literal), processors, grep, regex extraction, stop rules,
      concurrency, delays, CSV/JSON/table output
- [x] Repeater: URL/file/history/stdin input, headers, body, editor, repeat, raw/body/header output

### Proxy
- [x] Plain HTTP forwarding
- [x] CONNECT tunnel passthrough
- [x] Optional TLS MITM with generated CA + per-host leaf certificates (rcgen)
- [x] CA show/export/info/regenerate
- [x] Request/response intercept console
- [x] Session headers, cookies and match/replace rules (honours `session.auto_apply`)
- [x] In-memory cookie jar updated from proxied `Set-Cookie` responses
- [x] Scope enforcement option
- [x] History + issue recording
- [x] Plugin hooks

### Scanner
- [x] Passive checks: missing security headers, cookie flags, mixed content,
      directory listing, password autocomplete, source maps, banners, secrets,
      JWT exposure, CORS, etc.
- [x] Active checks: XSS, SQLi, SSTI, LFI, open redirect, command injection,
      CRLF, NoSQL, SSRF, XXE, CORS, host-header, JWT
- [x] Insertion points: query, form, JSON, cookies, headers, path segments
- [x] Crawler/spider with scope, depth, page limits, delays
- [x] Issue de-duplication + severity/confidence model + evidence storage
- [x] Rate limiting, concurrency, timing checks
- [x] OOB integration for SSRF/XXE
- [x] Passive plugin hooks integrated into scan results

### OOB / Plugins / Reports
- [x] HTTP-only OOB collaborator (local listener, daemon, remote provider)
- [x] OOB start/stop/status/poll/clear/payload/url
- [x] External JSON-lines plugin protocol (request/response/passive hooks)
- [x] Plugin list/install-demo/remove/test/enable/disable
- [x] Reports: table, JSON, HTML, Burp XML, SARIF 2.1.0, Markdown
- [x] Severity filtering, statistics, evidence decoding

### CLI
- [x] Commands: proxy, ca, history, repeater, intruder, scan, spider, sitemap,
      decoder, comparer, sequencer, oob, scope, project, session, plugin, report, config
- [x] Hidden `__oob-serve` and `__plugin-demo`
- [x] Project auto-resolution (`--project`, `BURPCLI_PROJECT`, global current project)
- [x] Exit-code support via `scan --fail-on`

### Tests
- [x] `tests/common/mod.rs` local threaded HTTP server helper
- [x] Integration tests: HTTP client, redirects, cookies, chunked/gzip bodies
- [x] Integration tests: proxy forwarding, CONNECT, history recording, session cookies
- [x] Integration test: TLS MITM with trusted project CA
- [x] Integration tests: scanner (reflected XSS/SQLi), passive checks, spider, sitemap
- [x] Integration tests: intruder attack modes, markers in URLs, processors
- [x] CLI end-to-end tests (version/help/project/decoder/comparer/report/intruder)
- [x] OOB callback round-trip test
- [x] Plugin protocol round-trip test + scanner passive-plugin integration
- [x] 111 tests passing: 74 unit + 37 integration

### Documentation
- [x] `README.md` (features, install, quickstart, examples)
- [x] `docs/quickstart.md`
- [x] `docs/commands.md`
- [x] `docs/architecture.md`
- [x] `docs/scanner.md` (checks, insertion points, tuning)
- [x] `docs/intruder.md`
- [x] `docs/proxy-mitm.md` (CA install, interception, rules)
- [x] `docs/plugins.md` (JSON-lines protocol + example)
- [x] `docs/oob.md`
- [x] `docs/security-legal.md`
- [x] `docs/limitations.md` (HTTP-only OOB, no WebSocket interception, etc.)
- [x] `LICENSE` file (MIT)
- [x] `.gitignore` for build output, projects and CA material

## Verification

- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --all-targets -- -D warnings`
- [x] `cargo test`
- [x] `cargo build --release`
- [x] Manual smoke test: project/scope/session/CA, decoder, comparer, sequencer,
      OOB daemon, plugins, repeater, scan, spider, sitemap, intruder, all report
      formats, plain HTTP proxy forwarding, history
- [x] Git commit(s) / tag v1.0.0
- [ ] Optional: CI workflow, sample requests, example plugin

## Known Limitations
- OOB is HTTP-only; DNS callbacks require delegation (out of scope)
- WebSocket traffic is tunnelled but not inspected
- HTTP/1.1 only; no HTTP/2 or HTTP/3
- Blocking std networking + threads (no async runtime)
- Proxy history/issues use JSONL + locks rather than a database
- MITM requires installing the generated CA in clients
- Live proxy cookie-jar updates are not persisted to `session.json`
- Scanner is signature/differential based; no JS execution or blind SQLi extraction
- Plugins are unsandboxed external processes with one-process-per-invocation overhead

See [docs/limitations.md](docs/limitations.md) for the full list.
