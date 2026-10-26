# Scanner

`burpcli scan` (alias `burpcli scanner`) sends one baseline request, optionally crawls,
runs passive checks on every page, and drives active probes through the insertion
points of each request. Findings are de-duplicated and appended to
`<project>/issues.jsonl`.

```console
$ burpcli --project ./acme scan 'https://example.test/search?q=hello' --save-evidence
$ burpcli --project ./acme scan --request captured.txt --check xss --check sqli
$ burpcli --project ./acme scan 'https://example.test/' --passive --crawl-depth 2
```

A target can be a URL or a raw HTTP request file. When a raw request is used, its
`Host` header, scheme and body are preserved; this is the way to scan authenticated
POST, JSON, XML and cookie-bearing endpoints.

```console
$ burpcli --project ./acme scan --request login.txt --point form --check sqli
```

## Check selection

```console
$ burpcli scan --list-checks
```

Without `--check`, every active check is enabled. `--check` is repeatable and
`--skip` removes checks. Checks are also filtered by `checks` and `skip_checks` in
`project.toml`; `--passive` clears the active set entirely.

| Name | Applies to | Detection |
| --- | --- | --- |
| `xss` | point | Inject `<svg/onload=alert(1)>`; reports when the exact payload is reflected in an HTML response and was absent from the baseline. High. |
| `sqli` | point | Error-based quote probes (`'`, `"`, `')`, `1'`) matched against a DB error signature list; boolean differential (`1' AND '1'='1` vs `'2`); optional time-based `SLEEP`/`pg_sleep`/`WAITFOR` probes. High (error/time), Medium (boolean). |
| `ssti` | point | Injects `{{7919*7919}}`, `${...}`, `<%= ... %>`, `#{...}`; reports when `62710561` appears without the literal payload. High. |
| `lfi` | point | Traversal and absolute paths for `/etc/passwd` and `windows/win.ini`, matched by file signatures (`root:x:0:0:`, `[extensions]`, `for 16-bit app support`). High. |
| `redirect` | point | Injects `https://burpcli.invalid/redirect` and `//burpcli.invalid/redirect`; reports when the response `Location` contains the marker and the baseline did not. Medium. |
| `cmdi` | point | Echo markers via `;`, `|`, `$()`, backticks, `&`; optional `sleep`/`ping` timing probes. High. |
| `crlf` | point | Injects CRLF and percent-encoded CRLF with a random marker; reports when the marker appears in response headers. Medium. |
| `nosql` | point | MongoDB/BSON error signatures and a boolean expression pair. Medium. |
| `ssrf` | point | Requires OOB. Injects a unique callback URL and waits up to 4 seconds for an interaction. High. |
| `xxe` | request | Requires OOB and an XML-looking body. Inserts a `DOCTYPE` with an external parameter entity after the XML declaration and waits for a callback. High. |
| `cors` | request | Sends `Origin: https://burpcli.invalid` and `Origin: null`; reports reflection. High when `Access-Control-Allow-Credentials: true`, otherwise Medium. |
| `host-header` | request | Replaces `Host`, `X-Forwarded-Host` and `X-Forwarded-For` with `burpcli.invalid` in turn; reports reflection in body or `Location`. Medium, tentative. |
| `jwt` | request | Finds a JWT in a request header, retries with `alg=none`, and compares against a garbage-signature token. Reports when the unsigned token is accepted while the garbage token is rejected. High. |

Notes:

- XXE is request-level, not per insertion point. `--point` does not change it.
- `ssrf` and `xxe` silently do nothing without `--oob`; that is deliberate so scans
  never invent callbacks.
- Timing probes only run with `--timing` (or `timing_checks = true` in the project),
  and only when the baseline response took under 3 seconds. A probe must exceed
  4 seconds to count, so slow or jittery targets can produce false negatives.
- Detection is signature- and differential-based. It is intentionally conservative,
  but it is not a substitute for manual testing.

## Insertion points

The scanner derives points from the baseline request:

| Kind | Source |
| --- | --- |
| `query` | Every query-string parameter. |
| `form` | Fields of an `application/x-www-form-urlencoded` body. |
| `json` | Every string value in a JSON body, addressed by JSON pointer. Numbers, booleans and nulls are not injected. |
| `cookie` | Cookie pairs in the `Cookie` header. |
| `header` | `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Forwarded-Host`, `Origin` (created if absent). |
| `path` | Every non-empty path segment, excluding the query string. |

Limit the work with repeatable `--point` flags:

```console
$ burpcli scan 'https://example.test/search?q=x' --point query --point header
```

Payloads are percent-encoded for query, form and path positions, cookie-safe encoded
for cookies, and written verbatim into headers. `Content-Length` is recalculated for
form and JSON bodies.

## Passive checks

Passive checks run once per scanned response and never send extra traffic. The
following check IDs can appear in reports:

| Check | Trigger |
| --- | --- |
| `missing-sts` | HTTPS HTML response without `Strict-Transport-Security`. |
| `missing-csp` | HTML response without `Content-Security-Policy`. |
| `weak-csp` | CSP contains `unsafe-inline` or `unsafe-eval`. |
| `missing-frame-protection` | Neither `X-Frame-Options` nor CSP `frame-ancestors`. |
| `missing-nosniff` | No `X-Content-Type-Options`. |
| `missing-referrer-policy` | No `Referrer-Policy`. |
| `mixed-content` | HTTPS HTML page references `http://` resources. |
| `directory-listing` | Body looks like an auto-generated directory index. |
| `password-autocomplete` | Password inputs outnumber `autocomplete=off`/`new-password` declarations. |
| `server-banner` | `Server` header contains a version number. |
| `powered-by` | `X-Powered-By` is present. |
| `source-map` | Body references `sourceMappingURL`. |
| `cookie-flags` | A `Set-Cookie` misses `Secure` (HTTPS), `HttpOnly` or `SameSite`. |
| `cache-control` | A response that sets cookies lacks `Cache-Control: no-store`. |
| `cors-wildcard` | `Access-Control-Allow-Origin: *`, with higher severity when credentials are allowed. |
| `error-disclosure` | Stack traces, SQL errors or framework exceptions in the body. |
| `secret-exposure` | AWS keys, private keys, GitHub/Slack tokens, Google API keys or JWTs in the body. |
| `jwt-none` | A JWT in the body or `Set-Cookie` uses `alg=none`. |
| `jwt-no-expiry` | A signed JWT has no `exp` claim. |

Secrets are redacted in evidence (first six and last four characters only). Cookie
values and other potentially sensitive data are still stored in the project when
`--save-evidence` is used; protect the project directory accordingly.

## Crawling

`--crawl-depth N` runs the breadth-first crawler from the target first, records pages
in the sitemap, and scans each page. `--max-urls` caps the number of crawled pages
(default 100). Crawling stays on the target host and inside scope.

```console
$ burpcli scan 'https://example.test/' --crawl-depth 3 --max-urls 200 --delay 100
```

Depth 0 (the default) scans only the target request. Links are extracted from HTML
`href`/`src`/`action` attributes; JavaScript-generated links and form submissions are
not discovered. Use `burpcli spider` when you only want a sitemap.

## Timing, concurrency and rate limiting

| Option | Default | Effect |
| --- | --- | --- |
| `--concurrency` | 10 | Worker threads (clamped to 1-64 and to the number of jobs). |
| `--delay` | 0 | Minimum milliseconds between probe starts, shared by all workers. |
| `--timeout` | 15000 | Per-request timeout in milliseconds. |
| `--follow` | 0 | Follow up to N redirects while probing. |
| `--insecure` | off | Skip TLS verification. Prefer trusting the target CA instead. |
| `--user-agent` | burpcli version | Override the User-Agent. |

Because the limiter is global, `--delay 100` with concurrency 10 still starts at most
one request per 100 ms. This is the polite setting for shared or production-adjacent
systems.

## Scope

The target must be in scope. An empty include list is filled with the target host for
the duration of the scan. Exclusions always win. Add extra patterns with repeatable
`--scope`:

```console
$ burpcli scan 'https://example.test/' --scope 'https://api.example.test/*'
```

Out-of-scope links discovered while crawling are skipped. Redirects are followed only
if `--follow` is set; redirect targets are not scope-checked, so keep `--follow` low
when scanning a shared host.

## OOB checks

```console
$ burpcli scan 'https://example.test/' --check ssrf --check xxe --oob local
```

`--oob local` starts an ephemeral listener on `127.0.0.1` and logs interactions to
`<project>/oob/events.jsonl`. A target that cannot reach your machine will never
trigger the finding. To use an exposed collaborator, pass its base URL:

```console
$ burpcli oob start --bind 0.0.0.0 --public-url https://oob.example.test
$ burpcli scan 'https://example.test/' --check ssrf --oob https://oob.example.test
```

See [oob.md](oob.md) for exposure and token details.

## Output

The console summary lists each new finding with severity, confidence, URL and
parameter. Findings are always persisted to `issues.jsonl`; de-duplication uses
`check + method + URL + parameter`, so a second scan of the same URL will not add
duplicates but will not refresh evidence either.

Render a report immediately with `--format` and `--output`, or later with
`burpcli report`:

```console
$ burpcli scan 'https://example.test/' --format html --output reports/scan.html
$ burpcli report --format sarif --output reports/scan.sarif
```

`--min-severity` filters rendered output, `--title` sets the report title, and
`--fail-on high` exits 1 when a finding at or above that severity exists (useful in
CI). `--save-evidence` stores the full request and response (base64) with each issue.

## Tuning false positives

- Re-scan with `--check` narrowed to one class to confirm a finding manually.
- Boolean SQLi/NoSQLi hits depend on similarity thresholds (true payload >= 0.92,
  false payload < 0.85); dynamic pages frequently fail these thresholds and are
  reported only as Medium.
- XSS requires byte-identical reflection. Contexts that encode only some characters,
  or that reflect the payload after sanitisation, are not reported.
- The LFI and command-injection checks look for unambiguous signatures on purpose.
  Absence of a finding is not evidence of safety.
- `--timing` doubles or triples request volume. Run it against a staging system,
  ideally with `--delay`.

## Limitations

See [limitations.md](limitations.md). The most relevant scanner limits:

- HTTP/1.1 only; no HTTP/2 request generation.
- No JavaScript execution, so single-page-app routes are not crawled.
- No authenticated crawl orchestration: use `session login`/macros first, or scan a
  captured authenticated request.
- No blind SQLi data extraction or payload encoding permutations; this is a detector,
  not an exploitation framework.
- Finding IDs are content-derived; re-scanning with different evidence does not update
  an existing issue record.
