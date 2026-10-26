# Intruder

`burpcli intruder` automates request generation over marked payload positions. It
supports Burp-style `§...§` markers, four attack types, list/file/range payloads,
processors, grep/extract rules and table/CSV/JSON output.

```console
$ burpcli --project ./acme intruder \
    --url 'https://example.test/login' \
    --data 'user=§admin§&pass=§pw§' \
    --attack cluster-bomb \
    --payload 'list:admin,root' \
    --payload 'list:admin,password' \
    --grep 'Welcome' --extract 'session=session=([a-f0-9]+)'
```

The template can come from a URL (`--url`), a raw request file (`--file`), a history
entry (`--history ID`), or stdin when no source option is given.

## Markers

A position is a pair of `§` characters. The payload replaces everything between the
pair, including the markers:

```text
GET /search?q=§hello§&lang=en HTTP/1.1
Host: example.test

user=§admin§&pass=§secret§
```

Markers may appear in:

- the request target (path and query),
- header values,
- the body (any bytes, including binary).

Markers may not appear in header names, the method or the HTTP version. Every opening
marker needs a closing partner; unclosed markers abort the attack before any request
is sent.

`--wrap TEXT` is a shortcut for simple GET/POST experiments: it wraps every occurrence
of `TEXT` in the request target and body with markers. It does not touch headers, and
it fails if the text is not found.

```console
$ burpcli intruder --url 'https://example.test/search?q=hello' --wrap hello \
    --payload 'list:<script>,safe'
```

## Attack types

| `--attack` | Payload sets | Behaviour |
| --- | --- | --- |
| `sniper` | First set only | Each position is attacked separately; all other positions are replaced with an empty string. |
| `battering-ram` | First set only | Every position receives the same payload in each request. |
| `pitchfork` | One set per position | Sets advance in lock-step; the attack stops at the shortest set. |
| `cluster-bomb` | One set per position | Sends the full Cartesian product of all sets. |

Pitchfork and cluster-bomb require at least one `--payload` per marker; extra sets
beyond the marker count are ignored. Sniper and battering-ram always use the first
set, even if more are supplied.

Generated requests are capped by `--max-requests`. The cap is applied while generating
combinations, so a huge cluster-bomb is truncated rather than materialised in full.

## Payload sources

`--payload` is repeatable. Each value is one of:

| Spec | Meaning |
| --- | --- |
| `list:a,b,c` | Comma-separated values, trimmed. |
| `file:path` or `@path` | One payload per line. Blank lines and lines starting with `#` are skipped. A bare existing file path is also accepted. |
| `numbers:1-100` | Inclusive integer range. |
| `numbers:1-100:2` | Range with a step. |
| `numbers:001-010` | Zero-padded range; the width is preserved. |
| `hex:0a-0f` | Inclusive hexadecimal range, zero-padded to the input width. |
| anything else | A single literal payload. |

A relative `file:` path is resolved against the current working directory, not the
project directory.

## Processors

`--processor` is repeatable and applies to every payload in every set, in the order
given. Processors are applied after the payload source is expanded, so one source can
be reused with different transformations by running separate attacks.

| Processor | Effect |
| --- | --- |
| `upper`, `lower`, `trim` | Case conversion / whitespace trim. |
| `url`, `urlencode` | Percent-encode the payload. |
| `base64` | Standard base64. |
| `hex` | Hex-encode bytes. |
| `md5`, `sha1`, `sha256` | Hex digest of the payload. |
| `prefix:TEXT` | Prepend text. |
| `suffix:TEXT` | Append text. |
| `replace:from=>to` | Literal replacement. |
| `regex:pattern=>replacement` | Regex replacement (`$1` style groups are supported by the regex crate). |

Processors can fail (for example an invalid regex), which aborts the run before any
request is sent.

## Grep, extraction and stop rules

`--grep` is repeatable and records which patterns matched each response. A pattern can
be:

- a literal or `*` wildcard string, matched case-insensitively against the body and
  the header block,
- `status:200` or `status:200,302`,
- `size>1000` or `size<500` (body length in bytes).

`--extract NAME=REGEX` is repeatable. The first capture group is stored, or the whole
match when the regex has no group. Extraction runs against the response body only. The
name becomes an extra column in table/CSV output and a key in JSON output.

`--stop-on TEXT` ends the attack when a response matches the pattern. In-flight
requests finish; queued requests are dropped. The run reports whether it stopped early.

Grep and extraction failures are recorded per result (`error` in JSON/CSV) and do not
abort the attack.

## Concurrency, delays and limits

| Option | Default | Meaning |
| --- | --- | --- |
| `--concurrency` | 10 | Worker threads. |
| `--delay` | 0 | Minimum milliseconds between request starts, globally. |
| `--max-requests` | unlimited | Hard cap on generated requests. |
| `--timeout` | 15000 | Per-request timeout in milliseconds. |
| `--follow` | 0 | Redirects to follow. |
| `--insecure` | off | Skip TLS verification. |
| `--no-session` | off | Do not apply project cookies/headers/rules. |
| `--user-agent` | burpcli version | Override the User-Agent. |

Results are sorted by generation index regardless of completion order. The console
progress line is suppressed by `--quiet`.

## Output

The default table prints index, status, length, duration, payloads, grep matches and
one column per extracted name. `--show N` limits printed rows (default 25; `0` prints
all). The table is not printed when `--output` is used.

```console
$ burpcli intruder --url ... --payload ... --format json
$ burpcli intruder --url ... --payload ... --output results.csv
$ burpcli intruder --url ... --payload ... --output results.json --save-responses
```

`--format` accepts `table`, `csv` or `json`. Without it, the format is inferred from
the output extension (`.csv`, `.json`, otherwise table).

- CSV is RFC 4180 style: quoted fields, CRLF line endings, columns
  `index,status,length,duration_ms,url,payload1..N,<extracts>,grep,error`.
- JSON is an array of result objects. It includes `payloads`, `grep`, `extracted`,
  `error` and, when `--save-responses` is set, `response_b64`.
- A failed request has status `0` and an `error` string.

A one-line summary reports request count, positions, generated count, grep hits,
length outliers, errors and duration.

## Examples

### Credential stuffing against a login form

```console
$ burpcli intruder --url 'https://example.test/login' \
    --data 'user=§admin§&pass=§secret§' \
    --attack cluster-bomb \
    --payload 'list:admin,root' \
    --payload 'file:passwords.txt' \
    --grep 'status:302' \
    --extract 'csrf=name="csrf" value="([^"]+)"' \
    --concurrency 5 --delay 200
```

### Parameter fuzzing with numeric IDs

```console
$ burpcli intruder --url 'https://example.test/api/users/1' --wrap 1 \
    --payload 'numbers:1-1000' \
    --grep 'status:200' --output users.csv --show 0
```

### Sniper over every parameter of a captured request

```console
$ burpcli intruder --file request.txt --attack sniper \
    --payload 'file:payloads.txt' --save-responses --format json
```

### Authenticated attack using stored session state

```console
$ burpcli session login --request login.txt
$ burpcli intruder --url 'https://example.test/api/search?q=§x§' \
    --payload 'list:test,admin'
```

Project cookies, static headers and match/replace rules are applied by default; use
`--no-session` to send the template exactly as written.

## Limitations

- HTTP/1.1 only.
- No built-in payload list beyond what you supply; put wordlists in
  `<project>/wordlists/` or use `file:`.
- No recursive grep/extract across redirect chains: only the final response is
  inspected.
- No per-request retry logic. On flaky networks, raise `--timeout` and lower
  `--concurrency`.
- Markers are literal `§`; there is no escaping mechanism for a legitimate `§` in the
  template. Use a different placeholder in the source and edit the template, or avoid
  that character in payload positions.
- Sniper/battering-ram ignore extra payload sets rather than erroring; check the
  generated count in the summary.

See [commands.md](commands.md) for the full CLI surface and
[limitations.md](limitations.md) for toolkit-wide constraints.
