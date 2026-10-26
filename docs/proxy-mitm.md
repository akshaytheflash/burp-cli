# Proxy and TLS interception

`burpcli proxy` is a forward HTTP proxy with optional TLS interception. It records
traffic to the project history, applies session rules and plugin hooks, and can pause
requests and responses on the console.

```console
$ burpcli --project ./acme proxy --port 8080
burpcli proxy listening on http://127.0.0.1:8080
project : ./acme
mode    : HTTP + CONNECT tunnel
```

Point clients at `http://127.0.0.1:8080`:

```console
$ curl -x http://127.0.0.1:8080 http://example.test/
$ curl -x http://127.0.0.1:8080 https://example.test/    # tunnelled, not inspected
```

Defaults come from `project.toml` (`[proxy]`), usually `127.0.0.1:8080`. CLI options
override them for one run.

## Modes

### Plain HTTP

Absolute-form requests (`GET http://host/path HTTP/1.1`) are parsed, passed through the
session/plugin/intercept pipeline, sent with the built-in HTTP client, and written back
with `Connection: close`. Hop-by-hop headers (`Connection`, `Keep-Alive`,
`Proxy-Connection`, `Transfer-Encoding`) are removed from the response.

### CONNECT tunnel (default for HTTPS)

Without `--mitm`, the proxy answers `CONNECT host:port` with `200 Connection
Established` and copies bytes in both directions. TLS is end-to-end between the client
and the origin, so certificates, HTTP/2, WebSockets and non-HTTP protocols inside the
tunnel are untouched. The proxy records a single history entry tagged `connect` with
the target and the 200 response, but cannot see the requests inside.

### TLS interception (`--mitm`)

With `--mitm`, the proxy terminates TLS using a certificate generated on demand for
the requested host, then speaks plain HTTP/1.1 to the origin. This exposes HTTPS
requests to history, rules, plugins and the scanner hooks.

```console
$ burpcli --project ./acme ca export -o ./acme/ca/burpcli-ca.pem
$ burpcli --project ./acme proxy --port 8080 --mitm
```

The client must trust the project CA. Until it does, browsers show certificate errors
and strict clients refuse the connection.

## The project CA

The CA is generated on first use by `ca show`, `ca export`, `ca info` or starting the
proxy with `--mitm`, and stored in:

| File | Purpose |
| --- | --- |
| `<project>/ca/burpcli-ca.pem` | CA certificate (public). Install this in clients. |
| `<project>/ca/burpcli-ca.key` | CA private key (secret). Never share or commit it. |

`ca export` defaults to `<project>/reports/burpcli-ca.pem`; pass `-o` to choose a path.
`ca info` prints both paths, whether they exist, and a short SHA-256 fingerprint.
`ca regenerate --force` deletes and recreates the CA, invalidating every previously
issued leaf certificate; clients must reinstall the new CA.

Leaf certificates are created per host on demand, signed by the project CA, and cached
in memory for the life of the proxy process. They are not written to disk. The CA key
is unencrypted PEM; anyone who can read it can impersonate any host to clients that
trust the CA.

### Installing the CA

Only install the CA in a client you control, and remove it when the engagement ends.

- **Windows (current user):**
  `certutil -addstore -user Root burpcli-ca.pem`
- **macOS:**
  `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain burpcli-ca.pem`
- **Linux:** import into the browser or system store you actually use (for example
  `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n burpcli -i burpcli-ca.pem` for
  NSS-based browsers).
- **Firefox:** uses its own certificate store; import under Settings > Privacy &
  Security > Certificates > View Certificates > Authorities.
- **iOS/Android:** install the certificate profile and, on modern Android, configure a
  network security config if the app does not trust user CAs. Certificate pinning
  cannot be bypassed by installing a CA.

Verify the fingerprint out of band before trusting a CA file.

## Intercepting traffic

```console
$ burpcli --project ./acme proxy --intercept
```

`--intercept` enables both directions. Use `--intercept-requests` or
`--intercept-responses` to pause one side only. Interception requires an interactive
stdin; when stdin is redirected the prompts are disabled and traffic flows normally.

At each prompt:

| Input | Action |
| --- | --- |
| Enter, `f`, `forward` | Forward the message unchanged. |
| `d`, `drop` | Drop it. Requests get a synthetic `403`; responses are replaced with `403`. |
| `e`, `edit` | Open the message in `$VISUAL`/`$EDITOR`, then reparse it. Invalid edits are reported and the original is kept. |
| `q`, `quit` | Disable interception for the rest of the process and forward. |

Prompts are serialised, so concurrent browser connections queue instead of
interleaving output.

## Session rules and headers

Before forwarding, the proxy applies:

1. Scope enforcement (`--only-in-scope`).
2. When `session.auto_apply` is on (the default): static headers from
   `session header`, cookies from `session set-cookie`, and match/replace rules for the
   request direction.

   Cookies are merged into an existing `Cookie` header without replacing values the
   client already sent. Use `session auto off` to pass traffic through untouched.

3. Request plugins.
4. Interactive request interception.

After the response arrives:

1. When `session.auto_apply` is on: match/replace rules for the response direction.
2. Response plugins and their findings.
3. Interactive response interception.
4. History recording.

`Set-Cookie` headers received through the proxy update an in-memory cookie jar for the
life of the proxy process, so later requests pick up new session cookies. That live jar
is not written back to `session.json`; run `session login` or `session set-cookie` to
persist cookies across restarts. The client's own `Cookie` header is preserved.

Rules are literal by default; pass `--regex` when creating one. See
`burpcli session --help` and [commands.md](commands.md#session).

## Scope

`--only-in-scope` answers `403` to out-of-scope plain requests and refuses out-of-scope
`CONNECT` targets before establishing a tunnel. Scope patterns are the same wildcard
patterns used by the scanner; exclusions always win. An empty include list means
everything is allowed, so add includes before relying on enforcement.

```console
$ burpcli --project ./acme scope add 'https://app.example.test/*'
$ burpcli --project ./acme proxy --only-in-scope
```

Blocked and dropped exchanges are still recorded in history, tagged `blocked` or
`dropped`.

## Upstream TLS verification

The proxy does **not** verify origin certificates by default, matching Burp's default
and making self-signed lab targets usable. Pass `--verify-upstream` to validate against
the client trust store (the bundled Mozilla roots); this is the safer setting for
production traffic.

```console
$ burpcli proxy --mitm --verify-upstream
```

The proxy has no client-certificate support for origins, so mTLS-protected upstreams
must be reached through a blind tunnel or tested with the scanner's request mode.

## History

Every plain exchange and every intercepted HTTPS exchange is appended to
`<project>/history.jsonl`. Entries include method, URL, status, MIME type, duration,
tags, and base64 request/response bytes.

```console
$ burpcli history list --project ./acme
$ burpcli history show 42 --project ./acme
$ burpcli history show 42 --project ./acme --request-only --raw
```

Requests dropped by a plugin or the intercept console have no response and a
`dropped` tag. Upstream failures produce a synthetic `502` and an `error` tag. Plugin
findings are written to `issues.jsonl`.

## Plugins in the proxy

If plugins are enabled (`plugins.enabled = true`), each request/response hook runs its
subprocess synchronously in the proxy pipeline. A slow plugin adds latency to every
exchange; a plugin that hangs is killed after its timeout. Request plugins can drop a
request (`"action":"drop"`) or replace it. See [plugins.md](plugins.md).

## Operational notes

- The listener is non-blocking with a polling accept loop; each accepted connection
  gets its own thread. There is no connection limit. Do not expose the proxy to an
  untrusted network.
- Responses are read fully into memory (up to 64 MiB). Streaming downloads and
  server-sent events are not proxied incrementally.
- The proxy sets `Connection: close` on forwarded responses; it is not a
  performance-oriented reverse proxy.
- Long-lived blind tunnels have a 300-second socket read timeout per read.
- History writes take an advisory lock, so the proxy can run while other `burpcli`
  commands read or append history.
- Regenerating the CA while the proxy runs does not affect the already-loaded CA; stop
  and restart the proxy.

## Limitations

- **HTTP/1.1 only.** Intercepted traffic is downgraded to HTTP/1.1; upstream HTTP/2 is
  not spoken. Blind tunnels can carry whatever the client and server negotiate.
- **No WebSocket upgrades in the inspected path.** A `101 Switching Protocols`
  response is treated as a normal response and the connection is closed. Use a blind
  tunnel for `wss://` or `ws://`.
- **No transparent interception, PAC server or SOCKS mode.**
- **No response streaming**, no range-request special handling and no cache.
- **No HTTP/2 or QUIC**, so some modern clients may fall back or fail when MITM is
  enabled.
- **Certificate pinning** in mobile apps and some desktop clients cannot be bypassed by
  trusting the CA.
- **No mTLS to origins** and no custom client certificates.
- Accepting the CA means accepting that the proxy can read and modify all TLS traffic
  from that client. Treat the CA key as a high-value secret.
