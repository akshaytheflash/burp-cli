# Command reference

Every command accepts `--help`. This page documents behaviour and the most useful
options; `--help` remains authoritative for the exact flag list of your build.

```
burpcli [GLOBAL OPTIONS] <COMMAND> [OPTIONS]
```

## Global options

| Option | Meaning |
| --- | --- |
| `--project <DIR>` | Project directory. Defaults to `$BURPCLI_PROJECT`, the project selected with `burpcli project use`, then `./.burpcli`. |
| `--color auto\|always\|never` | Colour output policy (default `auto`). `NO_COLOR` is honoured. |
| `-v`, `--verbose` | Extra diagnostics on stderr. |
| `-q`, `--quiet` | Suppress progress output (results still print). |
| `-V`, `--version` | Print the version. |

Global options can be written before or after the subcommand. `BURPCLI_HOME` overrides
the directory holding the global `config.toml` (default `~/.burpcli`).

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Error (bad input, network failure, missing project, or `scan --fail-on` threshold exceeded). |

## proxy

```console
burpcli proxy [--bind ADDR] [--port PORT] [--mitm] [--intercept]
              [--intercept-requests] [--intercept-responses]
              [--only-in-scope] [--verify-upstream] [--timeout MS]
```

Starts the intercepting proxy and blocks until Ctrl+C. Defaults come from
`project.toml` (`bind = "127.0.0.1"`, `port = 8080`).

- `--mitm` terminates TLS with a certificate generated from the project CA.
- `--intercept` pauses every request and response. At the prompt: Enter/`f` forwards,
  `d` drops, `e` opens the message in `$VISUAL`/`$EDITOR`.
- `--only-in-scope` returns `403` for out-of-scope requests and `CONNECT` targets.
- `--verify-upstream` validates origin certificates. It is off by default so
  self-signed lab targets work; turn it on for production traffic.
- `--timeout` is the client socket timeout in milliseconds (default from project scan
  settings, normally `15000`).

Traffic is appended to `history.jsonl`; blocked/dropped entries are tagged. See
[proxy-mitm.md](proxy-mitm.md).

## ca

```
burpcli ca show
burpcli ca export [-o PATH]
burpcli ca info
burpcli ca regenerate [--force]
```

`show` prints the PEM certificate to stdout, and `info` prints the certificate and key
paths plus the SHA-256 fingerprint. `export` copies the certificate to
`<project>/reports/burpcli-ca.pem` by default; pass `-o PATH` to choose another
location. `regenerate` requires `--force`; there is no interactive confirmation, and
invalidates previously issued leaf certificates. The CA lives at
`<project>/ca/burpcli-ca.pem` with its private key at `<project>/ca/burpcli-ca.key`.

## history

```
burpcli history list [--method M] [--status CODE] [--host H] [--search TEXT]
                     [--tag TAG] [--in-scope] [--limit N] [--offset N] [--json]
burpcli history show <ID> [--request-only|--response-only] [--raw] [--json]
                          [--save-request PATH] [--save-response PATH]
burpcli history delete <ID>
burpcli history clear [--yes]
burpcli history note <ID> <TEXT>
burpcli history tag <ID> <TAG>...
burpcli history untag <ID> <TAG>...
burpcli history stats [--json]
```

IDs are assigned by the history store and are stable. `list` defaults to 100 entries;
`show --raw` writes raw bytes (may corrupt the terminal for binary bodies).
`clear` asks for confirmation on a TTY unless `--yes` is given.

## repeater

```console
burpcli repeater (--url URL | --file PATH | --history ID)
                 [--method METHOD] [--header 'Name: value']... [--data DATA]
                 [--edit] [--raw | --headers-only | --body-only | --json]
                 [--repeat N] [--save-response PATH]
                 [--no-session] [--no-save] [--insecure]
                 [--follow N] [--timeout MS] [--user-agent UA]
```

Sends one request and prints the response. Defaults:

- method `GET` (or `POST` when `--data` is given),
- no redirects (`--follow` to change),
- project session cookies/headers applied unless `--no-session`,
- every exchange saved to history unless `--no-save`,
- output is a readable request/response; `--json` is convenient for scripting and
  includes status, headers, body and timing.

`--repeat N` sends the request N times and reports each response; useful for caching
and race-condition experiments.

## intruder

```console
burpcli intruder (--url URL | --file PATH | --history ID)
                 --payload SPEC [--payload SPEC]...
                 [--wrap TEXT] [--attack TYPE] [--processor SPEC]...
                 [--grep TEXT]... [--extract NAME=REGEX]... [--stop-on TEXT]...
                 [--concurrency N] [--delay MS] [--max-requests N]
                 [--save-responses] [--output PATH] [--format table|csv|json]
                 [--show N] [--insecure] [--follow N] [--timeout MS]
                 [--no-session] [--user-agent UA]
```

Insertion points are `§...§` pairs in the request target, headers or body, e.g.
`user=§admin§&pass=§pw§`. Each pair is one position; the payload replaces the whole
marked span. `--wrap hello` marks every occurrence of `hello` in a request built from
`--url`.

| `--attack` | Semantics |
| --- | --- |
| `sniper` | One payload set; each position is attacked separately, other positions empty. |
| `battering-ram` | One payload set; the same payload fills every position. |
| `pitchfork` | One set per position; sets advance in lock-step to the shortest length. |
| `cluster-bomb` | One set per position; every combination is sent. |

Payload specs: `list:a,b,c`, `file:path` / `@path`, `numbers:1-100`,
`numbers:1-100:2`, `numbers:001-010`, `hex:0a-0f`, or a single literal. Processors:
`upper`, `lower`, `trim`, `url`, `base64`, `hex`, `md5`, `sha1`, `sha256`,
`prefix:TEXT`, `suffix:TEXT`, `replace:from=>to`, `regex:pattern=>replacement`.

`--grep` records whether the text appears in the response; `--extract` captures a
regex group into a named column; `--stop-on` ends the attack when the text appears.
`--output` infers CSV or JSON from its extension unless `--format` is explicit.
See [intruder.md](intruder.md).

## scan (alias: scanner)

```console
burpcli scan [TARGET | --request PATH]
             [--check NAME]... [--skip NAME]... [--list-checks]
             [--point KIND]... [--passive] [--timing]
             [--crawl-depth N] [--max-urls N]
             [--concurrency N] [--timeout MS] [--delay MS]
             [--follow N] [--insecure] [--save-evidence]
             [--user-agent UA] [--scope PATTERN]...
             [--oob local|URL]
             [--format FMT] [--output PATH] [--min-severity S]
             [--title TITLE] [--fail-on S]
```

Scans a URL or a raw request file. Without `--check`, every applicable active check
runs against every insertion point. `--point` is repeatable (`query`, `form`, `json`,
`cookie`, `header`, `path`). `--passive` runs only passive checks. `--crawl-depth`
crawls first and scans each discovered page; `--max-urls` caps the crawl.

`--oob local` starts an ephemeral local collaborator for SSRF/XXE; pass a base URL to
use an existing one. `--format` renders a report immediately, and `--fail-on high`
makes the command exit `1` when any finding meets the threshold. Findings are
de-duplicated and appended to `issues.jsonl`.

## spider

```console
burpcli spider <SEED> [--max-pages N] [--max-depth N] [--delay MS]
               [--insecure] [--user-agent UA] [--any-host]
               [--passive] [--json] [--timeout MS]
```

Breadth-first crawl that stores pages in `sitemap.json`. Defaults: 100 pages, depth 3,
same host only. `--any-host` follows links to other hosts (still useful only if they
are in scope). `--passive` runs passive checks on each crawled response.

## sitemap

```
burpcli sitemap tree [--limit N] [--json]
burpcli sitemap list [--search TEXT] [--limit N] [--json]
burpcli sitemap show <URL>
burpcli sitemap remove <URL>
burpcli sitemap clear
burpcli sitemap add <URL> [--insecure]
burpcli sitemap import-history [--limit N]
```

`tree` prints a host/path tree; `list` prints entries with status, content type and
length; `show` accepts an exact URL or substring. `import-history` seeds the sitemap
from stored responses.

## decoder

```console
burpcli decoder [INPUT] [--file PATH | --stdin]
                [--codec NAME]... [--encode]
                [--smart] [--identify] [--list]
                [--jwt | --jwt-sign HS256|HS384|HS512 | --jwt-none]
                [--secret SECRET] [--set KEY=VALUE]...
                [--output PATH]
```

Codecs are applied in the order given. Available codecs: `base64`, `base64url`, `hex`,
`url`, `html`, `unicode`, `gzip`, `deflate`, `rot13`, `binary`, `md5`, `sha1`,
`sha256`, `jwt`. Without `--codec`, a small set of common decodings is attempted;
`--smart` repeatedly detects and applies encodings; `--identify` reports likely
encodings without transforming.

JWT helpers decode into header/claims, re-sign with an HMAC secret (`--jwt-sign` plus
`--secret`, optional `--set` claims), or rewrite to `alg=none` (`--jwt-none`).

```console
$ burpcli decoder 'aGVsbG8=' --codec base64
hello
$ burpcli decoder 'hello world' --codec base64 --encode
aGVsbG8gd29ybGQ=
$ burpcli decoder --file token.jwt --jwt
```

## comparer

```console
burpcli comparer <A> [B] [--file-a PATH] [--file-b PATH]
                 [--mode lines|words|bytes] [--context N] [--json] [--output PATH]
```

Inputs may be literal text, file paths, or `@file`. Default mode is `lines`; `words`
compares whitespace-delimited units and `bytes` hexdumps both inputs. Output is a
unified diff plus added/removed/unchanged counts and a similarity percentage. `--json`
returns these statistics and hunks.

## sequencer

```console
burpcli sequencer (--file PATH | --url URL)
                  [--count N] [--extract SPEC] [--delay MS]
                  [--insecure] [--timeout MS] [--user-agent UA]
                  [--save-samples PATH] [--json]
```

Reads one token per line from a file, or samples tokens from a URL with `--extract`:
`cookie:NAME`, `header:NAME`, `body:REGEX`, or `location`. The analysis reports sample
count, alphabet size, Shannon entropy per character and in total, per-position
entropy, character-class coverage, repeated-token count, serial correlation and a
verdict (`STATIC`, `PREDICTABLE`, `WEAK`, `STRONG`). It is a statistical aid, not a
proof that a token is cryptographically secure.

## oob

```
burpcli oob start [--bind ADDR] [--port N] [--public-url URL] [--foreground] [--json]
burpcli oob stop
burpcli oob status [--json]
burpcli oob poll [--token TOKEN] [--json]
burpcli oob clear
burpcli oob payload [--token TOKEN] [--base-url URL]
burpcli oob url
```

`start` daemonises by default and prints the base URL and control status; use
`--foreground` to keep it attached. `payload` prints a unique
`<base>/oob/<token>` URL. Running interactions are appended to
`<project>/oob/events.jsonl`; `poll` prints them, optionally filtered by token.
The management API lives under `/__burpcli/` (`health`, `poll`, `shutdown`). See
[oob.md](oob.md).

## scope

```
burpcli scope list [--json]
burpcli scope add <PATTERN> [--exclude]
burpcli scope remove <PATTERN>
burpcli scope clear
burpcli scope check <URL>
```

Patterns may be full URLs with wildcards (`https://app.test/api/*`), a bare host
(`app.test`) or a host wildcard (`*.app.test:8443`). Exclusions win over inclusions.
An empty include list allows everything (excluding any exclusions); scans add the
target's host automatically before checking scope.

## project

```
burpcli project create [PATH] [--name NAME] [--force]
burpcli project list [--json]
burpcli project use <PATH>
burpcli project current
burpcli project info [--json]
burpcli project path
burpcli project delete [PATH] [--force]
```

`create` initialises the directory and registers it in the global config; `use` selects
it for subsequent commands. `delete` removes the directory and its registration after
confirmation (`--force` skips it). Without `PATH`, `create` and `delete` use the current
project directory.

## session

```
burpcli session show [--json]
burpcli session clear
burpcli session set-cookie <DOMAIN> <NAME> <VALUE> [--secure]
burpcli session remove-cookie <DOMAIN> <NAME>
burpcli session header 'Name: value'
burpcli session remove-header <NAME>
burpcli session headers
burpcli session rule <PATTERN> <REPLACE> [--regex] [--direction request|response|both] [--disabled]
burpcli session rules
burpcli session remove-rule <INDEX>
burpcli session auto on|off
burpcli session login [--request PATH] [--insecure] [--timeout MS]
burpcli session macro-add <FILE>
burpcli session macro-list
burpcli session macro-clear
```

Cookies are applied to matching domains; static headers are added when absent;
match/replace rules run on the configured direction. `auto` toggles automatic session
handling. `login` replays macro request files in order and stores any refreshed
cookies, which is useful before a scan that depends on authentication.

## plugin

```
burpcli plugin list [--json]
burpcli plugin install-demo
burpcli plugin remove <NAME>
burpcli plugin test [NAME]
burpcli plugin enable
burpcli plugin disable
```

Plugins live under `<project>/plugins/<name>/plugin.toml`. `test` starts the plugin,
sends a synthetic request, and prints the returned JSON. `enable`/`disable` flip
`plugins.enabled` in `project.toml`. See [plugins.md](plugins.md).

## report

```console
burpcli report [--format table|json|html|burp-xml|sarif|markdown]
               [--output PATH] [--min-severity info|low|medium|high]
               [--title TITLE] [--include-evidence] [--stats]
```

Renders stored findings. `table` prints to stdout; when `--output` names a directory
(or ends with a separator), the file name is derived from the project and format.
Extensions are normalised to the format (`txt`, `json`, `html`, `xml`, `sarif`, `md`).
`--stats` prints severity and per-check counts plus evidence size without rendering a
report.

## config

```
burpcli config show
burpcli config path
burpcli config get <KEY>
burpcli config set <KEY> <VALUE>
burpcli config unset <KEY>
burpcli config reset
```

Supported keys: `color`, `current_project`, `editor`, `user_agent`,
`default_timeout_ms`. The `projects` list is managed by `burpcli project` commands.
Edits are atomic.
