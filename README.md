# burpcli

A Burp Suite-style HTTP security testing toolkit for the terminal, written in Rust.
One self-contained binary provides an intercepting proxy, an active/passive scanner,
a crawler, an intruder, a repeater, an out-of-band collaborator, decoders, a comparer,
a token sequencer, a plugin host and multi-format reporting.

`burpcli` stores everything in plain files inside a project directory (JSONL history and
findings, JSON sitemap/session, TOML config), so results are easy to inspect, diff, grep
and commit. There is no database and no background service you cannot see.

## Feature overview

| Area | What you get |
| --- | --- |
| **Proxy** | Plain HTTP forwarding, `CONNECT` tunnelling, optional TLS interception with a project CA, request/response intercept console, match/replace rules, scope enforcement, proxy history |
| **Scanner** | 13 active checks (XSS, SQLi, SSTI, LFI, open redirect, command injection, CRLF, NoSQLi, SSRF, XXE, CORS, host-header injection, JWT `alg=none`), 19 passive checks, optional timing checks, evidence capture |
| **Spider** | Breadth-first crawler with depth/page limits, form and link extraction, sitemap persistence |
| **Intruder** | Sniper, battering-ram, pitchfork and cluster-bomb attacks; list/file/number/hex payloads; processors; grep, extraction and stop rules; CSV/JSON output |
| **Repeater** | Send raw requests from a URL, file or history entry; repeat, save, diffable JSON output |
| **Decoder** | base64/base64url, hex, URL, HTML, unicode, gzip, deflate, ROT13, binary, MD5/SHA-1/SHA-256, JWT decode/re-sign/`alg=none` |
| **Comparer** | Line, word and byte diffs with similarity statistics |
| **Sequencer** | Shannon entropy, per-position entropy, charset size, serial correlation and a verdict |
| **OOB** | Local collaborator daemon with unique callback URLs, polling API and event log; usable for SSRF/XXE/blind checks |
| **Plugins** | Language-agnostic external programs speaking JSON-lines over stdin/stdout, with request/response/passive hooks |
| **Reports** | Table, JSON, HTML, Burp XML, SARIF 2.1.0 and Markdown, with severity filters and optional evidence |
| **Projects** | Per-target scope, session cookies/headers/macros, findings, sitemap, CA, plugins and reports |

## Requirements

- Rust 1.85 or newer (edition 2021).
- No external services, databases or native TLS libraries are required; TLS uses
  `rustls` with the `ring` provider.
- On Windows, either the MSVC toolchain with Visual Studio Build Tools or the GNU
  toolchain with MinGW-w64 must be installed.

## Build and install

```console
$ git clone <repository> burp-cli
$ cd burp-cli
$ cargo build --release
$ ./target/release/burpcli --version
```

Install into `~/.cargo/bin`:

```console
$ cargo install --path .
```

Windows (GNU toolchain example):

```powershell
$env:PATH = "<mingw64>\bin;$env:PATH"
cargo +stable-x86_64-pc-windows-gnu build --release
```

## Quick start

```console
# Create a project and put the target in scope.
$ burpcli project create ./acme --name acme
$ burpcli --project ./acme scope add 'https://acme.test/*'

# Start the proxy (HTTP + CONNECT). Add --mitm to intercept HTTPS.
$ burpcli --project ./acme proxy --port 8080

# In another terminal: scan a URL, save evidence and write a report.
$ burpcli --project ./acme scan 'https://acme.test/search?q=test' \
    --check xss --check sqli --save-evidence \
    --format html --output reports/scan.html

# Inspect findings and export SARIF for CI.
$ burpcli --project ./acme report --stats
$ burpcli --project ./acme report --format sarif --output reports/scan.sarif
```

A five-minute guided tour lives in [docs/quickstart.md](docs/quickstart.md).

## Commands

```
proxy      Start the intercepting proxy
ca         Inspect or export the interception certificate authority
history    Browse and edit proxy history
repeater   Send a single request (optionally from a file or history)
intruder   Run an automated payload attack
scan       Scan a URL or saved request for vulnerabilities   (alias: scanner)
spider     Crawl a target and populate the sitemap
sitemap    Inspect the stored sitemap
decoder    Encode, decode and analyse data
comparer   Diff two inputs
sequencer  Analyse token randomness
oob        Manage the out-of-band interaction server
scope      Manage target scope
project    Create, select and inspect projects
session    Manage cookies, headers and match/replace rules
plugin     Manage external plugins
report     Generate reports from stored findings
config     Read or update global configuration
```

Every command supports `--help`; [docs/commands.md](docs/commands.md) is the full
reference. Global options (`--project`, `--color`, `--verbose`, `--quiet`) may appear
before or after the subcommand.

## Project layout

```
acme/
  project.toml        project settings (scope, scan/proxy defaults, plugins)
  history.jsonl       proxy/repeater history, one JSON object per line
  issues.jsonl        findings with optional base64 evidence
  sitemap.json        crawled/imported URLs and responses
  session.json        cookies, static headers, match/replace rules, macros
  ca/                 interception CA certificate and private key
  plugins/            one directory per plugin, each with plugin.toml
  reports/            default report output directory
  oob/                collaborator daemon state and JSONL interaction log
  wordlists/          place for payload wordlists
```

The default project directory is `./.burpcli`; `--project`, `$BURPCLI_PROJECT` and
`burpcli project use` select another one.

## Documentation

- [Quick start](docs/quickstart.md)
- [Command reference](docs/commands.md)
- [Architecture](docs/architecture.md)
- [Scanner](docs/scanner.md)
- [Intruder](docs/intruder.md)
- [Proxy and TLS interception](docs/proxy-mitm.md)
- [Plugins](docs/plugins.md)
- [Out-of-band collaborator](docs/oob.md)
- [Security and legal notes](docs/security-legal.md)
- [Limitations](docs/limitations.md)

## Tests

```console
$ cargo test
$ cargo clippy --all-targets -- -D warnings
```

The suite currently contains 111 tests: unit tests for parsers, protocol handling,
checks and analysis routines, plus integration tests that stand up local HTTP/HTTPS
servers on `127.0.0.1` and exercise the proxy, MITM, scanner, intruder, OOB server,
plugin protocol and the compiled CLI. No test contacts the public internet.

## Security and legal notice

`burpcli` is an offensive security tool. Use it only against systems you own or have
explicit written permission to test. Intercepting TLS traffic changes what your client
trusts; keep the project CA private and never install it on systems you do not control.
See [docs/security-legal.md](docs/security-legal.md).

## License

MIT. See [LICENSE](LICENSE).
