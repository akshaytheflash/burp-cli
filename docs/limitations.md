# Limitations

`burpcli` aims to be a practical terminal toolkit, not a drop-in replacement for the
Burp Suite UI. This page collects the constraints that matter when planning an
engagement. Individual feature pages have more detail.

## Protocol support

- **HTTP/1.1 only.** Requests are generated and parsed as HTTP/1.1. There is no HTTP/2
  or HTTP/3 client, no h2c, and no HTTP/2 pseudo-header model. Intercepted TLS traffic
  is downgraded to HTTP/1.1.
- **No WebSocket inspection.** A `101 Switching Protocols` response is treated as an
  ordinary response and the connection is closed. Blind `CONNECT` tunnels can carry
  `ws://`/`wss://`, but burpcli cannot see or modify frames.
- **No streaming.** Responses are buffered in memory, up to `[scan] max_body`
  (10 MiB by default). Server-sent events, long downloads and streaming APIs are read
  to the limit and then truncated.
- **No HTTP/1.1 request smuggling engine.** The parser is defensive, but it is not a
  smuggling research tool and does not model front-end/back-end disagreements.
- **No multipart builder.** You can send a captured multipart body verbatim or construct
  one in a raw request, but the scanner does not derive insertion points inside
  multipart parts.
- **No automatic retries.** A timeout or reset is a failed request. Lower concurrency or
  raise the timeout on unreliable links.

## Proxy

- Plain HTTP, blind `CONNECT` and TLS MITM only. There is no transparent proxy, PAC
  server, SOCKS mode, reverse-proxy mode or upstream proxy chaining UI.
- No response streaming, caching, compression re-encoding or range-request handling.
  Responses are forwarded with `Connection: close`.
- No client certificates to origins (mTLS). Use a blind tunnel when the origin requires
  one.
- Certificate pinning and Android network-security-config restrictions cannot be
  bypassed by trusting the project CA.
- The listener is non-blocking with one thread per connection and **no connection
  limit**. Do not expose it to an untrusted network.
- Interception is console-based and requires a TTY. Redirected stdin disables prompts.
  There is no GUI table, no per-host breakpoints and no intercept history browser.
- Plugins run synchronously in the request path, so slow plugins add latency to every
  exchange.
- Session cookies are loaded at proxy startup. Live `Set-Cookie` updates are kept in
  memory for the process lifetime but are not written back to `session.json`.
- Only one proxy process per port. There is no built-in authentication for proxy
  clients.

## Scanner

- **13 active checks and 19 passive checks**, all signature- or differential-based.
  Absence of a finding is not evidence of safety.
- **No JavaScript execution.** Single-page-app routes, dynamically generated links and
  client-side auth flows are not discovered. The crawler only follows `href`, `src` and
  `action` attributes in HTML.
- **No form submission.** The crawler records form action URLs but does not fill and
  submit forms. Capture a real request and scan that instead.
- **No authenticated crawl orchestration.** `session login` and macros replay a saved
  login request; there is no automatic re-authentication on `401`, CSRF-token refresh,
  or multi-step workflow engine.
- **Conservative detection.** XSS requires byte-identical reflection in an HTML
  response; SQLi/NoSQLi boolean checks rely on similarity thresholds; LFI and command
  injection require unambiguous signatures. Encoded, sanitised or context-dependent
  variants are frequently missed.
- **No blind SQLi extraction, exploitation, payload mutation or WAF-evasion engine.**
  This is a detector, not an exploitation framework.
- **Timing checks are optional and coarse.** `--timing` requires a baseline under
  3 seconds and a probe over 4 seconds. Slow targets produce false negatives, and the
  extra requests can be disruptive.
- **OOB waits are fixed at 4 seconds per SSRF/XXE probe.** A slow callback path yields a
  false negative. SSRF/XXE are disabled unless `--oob` is supplied.
- **Redirect targets are not scope-checked.** Keep `--follow` low when scanning shared
  hosts.
- **Issue de-duplication is permanent per project.** Re-scanning the same check, method,
  URL and parameter does not refresh the stored evidence. Delete `issues.jsonl` entries
  or use a fresh project to force a rewrite.
- **No HTTP/2, WebSocket or gRPC scanning**, and no JavaScript-aware DOM XSS analysis.

## Intruder

- HTTP/1.1 only.
- Markers are literal `§` characters with no escape mechanism.
- Sniper and battering-ram silently use only the first payload set; extra sets are
  ignored rather than rejected.
- No recursive grep/extract across redirect chains; only the final response is
  inspected.
- No automatic CSRF-token refresh between requests. Use session rules or a plugin if
  the target rotates tokens.
- No built-in wordlists beyond what you supply.
- Results are held in memory and written at the end; a very large attack can consume
  significant memory even with `--max-requests`.

## Repeater, decoder, comparer, sequencer

- Repeater sends one request at a time (optionally repeated) and has no tabs, history
  tree or side-by-side diff. Use `--save-response` and the comparer for diffs.
- The decoder supports the documented codecs only. It is not a general crypto toolkit;
  JWT signing is HMAC (`HS256`/`HS384`/`HS512`) or `alg=none`, with no RSA/ECDSA keys.
- The comparer is text-oriented. It handles bytes, but it is not a binary structural
  diff and does not understand image or archive formats.
- The sequencer reports statistical estimates from the sample you provide. Small samples
  produce unstable verdicts, and the tests are not a certification of randomness.

## OOB

- **HTTP only.** No DNS, SMTP or generic TCP callbacks. Blind SSRF that only resolves a
  name, and XXE that only performs DNS resolution, are invisible.
- No TLS listener; terminate TLS in a reverse proxy.
- No authentication on `health`/`poll`. Bind to loopback unless you intentionally expose
  it.
- No token expiry, payload encryption or rate limiting. Events grow until cleared.
- The listener handles one request per connection, reads at most 1 MiB of body, and does
  not support chunked uploads or HTTP/2.
- No automatic correlation of arbitrary interactions to findings; only the built-in
  SSRF/XXE checks consume tokens.

## Plugins

- Plugins are unsandboxed arbitrary code running with your privileges.
- One process per invocation: startup cost is added to every hooked exchange.
- Synchronous hooks in the proxy; no concurrency, priority or dependency ordering.
- No hot reload; restart the proxy or re-run the scan after changes.
- The scanner only invokes passive hooks; plugins cannot add active probes.
- Wire format is HTTP/1.1 messages only, with base64 bodies and ordered header arrays.

## Storage and concurrency

- Projects are plain files: JSONL history/issues, JSON sitemap/session, TOML config.
  There is no database, no query language and no transactional multi-record update.
- Cross-process writes use advisory lock files. They protect append operations on
  cooperating burpcli processes, but they are not a substitute for a database under
  heavy concurrent load.
- History and issue files grow without bound. Archive or delete projects periodically.
- There is no multi-user mode, access control or audit log beyond the recorded
  timestamps.
- Deleting a project directory deletes its CA and all evidence. There is no built-in
  recycle bin or backup.

## Reports

- Burp XML and SARIF are compatibility subsets, not byte-for-byte reproductions of
  Burp's or a specific vendor's schema. Validate SARIF with your CI consumer.
- HTML reports are static, self-contained files with no interactive filtering.
- Evidence is only as good as what was captured. Passive findings may not include a full
  response; `--save-evidence` increases disk usage substantially.
- Reports redact some secrets in passive evidence, but they do **not** redact cookies,
  authorization headers or request bodies. Review before sharing.

## Platform and operations

- Rust 1.85 or newer. The development and release verification for this repository used
  the Windows GNU toolchain; Linux and macOS are supported by the source but are not
  covered by the same local test run.
- Blocking standard-library networking with threads. There is no async runtime, no
  connection pool and no backpressure beyond concurrency limits.
- No installer, package repository, auto-update or telemetry.
- No built-in WAF evasion, IP rotation, upstream proxy pool or stealth mode. Traffic is
  ordinary HTTP and is easy to attribute.
- The tool does not clean up installed CAs, captured credentials or exposed OOB
  listeners for you. Do that as part of engagement close-out.

## Scope of testing

These limitations are intentional. They keep the tool auditable and predictable, but
they mean manual testing, a browser, a proxy-aware client and judgement remain
essential. See [security-legal.md](security-legal.md) before testing any system.
