# Architecture

`burpcli` is a single-threaded-per-connection, blocking-I/O toolkit. It deliberately
avoids an async runtime: the workloads are request/response tools where concurrency is
bounded by a small worker pool, and blocking code keeps the proxy, TLS handling and
plugin subprocesses straightforward to reason about.

## Crate layout

```
src/
  main.rs          thin binary entry point (errors -> stderr, exit 1)
  lib.rs           public module tree and version constant
  cli/
    mod.rs         clap root command, global options, project context
    admin.rs       proxy, ca, history, oob, scope, project, session, plugin, config
    requests.rs    repeater, intruder, history commands
    scanning.rs    scan, spider, sitemap, report commands
    tools.rs       decoder, comparer, sequencer
  http/
    message.rs     Request/Response parsing, serialisation, header helpers
    client.rs      blocking HTTP/1.1 client, redirects, proxying, chunked/gzip
    tls.rs         rustls client configuration and certificate loading
    cookies.rs     cookie jar with domain/path matching
  proxy/
    server.rs      listener, request pipeline, CONNECT tunnel, TLS MITM, intercept
    ca.rs          project certificate authority and per-host leaf certificates
  scanner/
    mod.rs         orchestration, scope, rate limiting, sitemap/issue persistence
    active.rs      insertion points and 13 active checks
    passive.rs     passive header/body/cookie checks
    crawl.rs       breadth-first crawler and link/form extraction
    issue.rs       Issue model, severity/confidence, JSONL store
  intruder.rs      payload sets, processors, attack generation, workers, output
  report.rs        severity filtering and six renderers
  oob.rs           collaborator server, daemon control, remote provider
  plugins.rs       manifests, JSON-lines protocol, subprocess invocation, demo
  session.rs       cookies, static headers, match/replace rules, macros
  scope.rs         wildcard scope compilation and matching
  sitemap.rs       URL tree persistence
  storage.rs       project layout, history store, cross-process locks
  config.rs        global config, project config, atomic writes
  decoder.rs       codecs, smart detection, JWT helpers
  comparer.rs      line/word/byte diff
  sequencer.rs     token statistics
  util.rs          base64, globs, tables, terminal helpers, command splitting
```

## Request flow

### Proxy

```
client socket
   |
   +-- CONNECT? -- no --> read HTTP request --> process_request
   |                                             |-- scope check
   |                                             |-- session headers/rules
   |                                             |-- request plugins
   |                                             |-- intercept console
   |                                             |-- upstream TLS/plain send
   |                                             |-- response plugins
   |                                             |-- intercept console
   |                                             `-- history + issues
   |
   `-- yes --> 200 Connection Established
                 |-- MITM: rustls acceptor -> read requests -> process_request
                 `-- blind: two-thread byte tunnel
```

The proxy uses one thread per accepted connection plus one handler thread per request
path. A `BufReader` may have read bytes beyond the request head; `CONNECT` forwards
that buffered prefix before starting the tunnel so pipelined clients do not lose data.
Fetching a URL on the client side uses the same `client::send` implementation as the
rest of the tool, which keeps redirect and proxy semantics identical.

### Scanner

`scanner::scan` accepts a `Target::Url` or `Target::Request`, resolves scope, builds a
shared `ClientOptions`/cookie jar, optionally crawls, then works through
insertion points. Points are discovered per request component:

- query parameters,
- `application/x-www-form-urlencoded` fields,
- JSON string values,
- cookies,
- selected headers (`Referer`, `User-Agent`, `X-Forwarded-Host`, and others),
- path segments.

Each active check receives an immutable baseline response and produces zero or more
`Issue`s. Point-level checks (XSS, SQLi, SSTI, LFI, redirect, command injection, CRLF,
NoSQLi, SSRF) run per insertion point; request-level checks (XXE, CORS, host header,
JWT) run once. Worker threads share a `RateLimiter`, an atomic request counter and a
pair of atomics for stop-on-first-finding / max URLs. Findings are de-duplicated by
check, method, URL and parameter before being appended to `issues.jsonl`.

Timing checks compare a baseline against delayed probes and are off unless `--timing`
is set. OOB checks inject a unique token URL and ask the provider whether a callback
arrived within a bounded timeout.

### Intruder

The template is parsed into literal segments and `§...§` positions. Attack generation
returns a `Vec<Vec<String>>` of payload tuples (bounded by `--max-requests`), then a
fixed-size worker pool pulls jobs from a queue, applies per-set processors, rebuilds
the request (including `Content-Length`), sends it, evaluates grep/extract/stop rules
and records a result. The stop flag is checked between jobs, so in-flight requests
finish before the attack ends.

## Storage

All state is file-based and human-readable:

| File | Format | Writer |
| --- | --- | --- |
| `project.toml` | TOML | project/config commands |
| `history.jsonl` | one JSON object per line | proxy, repeater |
| `issues.jsonl` | one JSON object per line | scanner, plugins, proxy |
| `sitemap.json` | pretty JSON | crawler, sitemap commands |
| `session.json` | pretty JSON | session commands |
| `oob/state.json` | daemon metadata | OOB daemon |
| `oob/events.jsonl` | interactions | OOB daemon |
| `ca/*.pem` | PEM | CA manager |
| `plugins/*/plugin.toml` | TOML | plugin commands |

Writes use a temp file plus rename (`config::atomic_write`) so readers never observe a
partial document. Appends and rewrites take an advisory lock file (`*.lock`) in
addition to an in-process mutex. Locks are broken after 60 seconds to recover from a
crashed process; this is a pragmatic trade-off rather than a full database guarantee.

History entries carry a monotonically increasing id. `history list` is stable across
processes because the id is recomputed from the file under the lock.

## TLS

- Client TLS: `rustls` + `ring`, with the bundled Mozilla root store
  (`webpki-roots`) plus any extra roots supplied by the caller.
- The proxy CA is created on first use from `rcgen` (key pair generated by `rcgen`),
  stored as PEM in `<project>/ca/`.
- Leaf certificates are generated per host on demand, include the host as a DNS/IP SAN,
  are signed by the project CA and cached in memory for the lifetime of the proxy.
- The CA private key is a plain PEM file. Protect the project directory; anyone with
  the key can impersonate any host to a client that trusts the CA.

## Concurrency model

| Component | Threads |
| --- | --- |
| Proxy | listener + one per client connection + per-request handler |
| Tunnel | one upload thread + current thread for download |
| Scanner | N workers (default 10), shared limiter and counters |
| Intruder | N workers (default 10) with a bounded queue |
| OOB daemon | accept loop + one thread per interaction |
| Plugins | one subprocess per hook invocation, with timeout and kill |

There is no global thread pool. Each subsystem bounds its own concurrency through CLI
options; plugin calls are serial per request because hooks run in pipeline order.

## Error handling

The library uses `anyhow::Result` with contextual messages. The binary prints
`burpcli: <chain>` and exits 1. Individual network failures inside scans and plugins
are collected into `errors` vectors rather than aborting the whole run, so a single
dead host does not discard other findings. Fatal configuration/parse errors abort
immediately.

## Testing strategy

- Unit tests live beside their modules and cover parsing, framing, encoding, scope,
  diffing, token statistics, report rendering and check logic.
- Integration tests (`tests/`) use `tests/common/mod.rs`, which starts real threaded
  HTTP and rustls HTTPS servers on ephemeral loopback ports. They never call the
  public internet and can run offline.
- CLI tests spawn the compiled binary with an isolated `BURPCLI_HOME` and temporary
  projects, asserting stdout/stderr and exit codes.
- The plugin test reuses the binary's hidden `__plugin-demo` subcommand, so the full
  subprocess protocol is exercised without external runtimes.
