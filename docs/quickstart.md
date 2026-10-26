# Quick start

This walkthrough uses `https://example.test` as a stand-in target. Replace it with a
host you are authorised to test.

## 1. Install

```console
$ cargo build --release
$ ./target/release/burpcli --version
burpcli 1.0.0
```

`cargo install --path .` puts `burpcli` on your `PATH`.

## 2. Create a project

Projects keep scope, history, findings, cookies and settings together.

```console
$ burpcli project create ./acme --name acme
created project acme at ./acme
$ burpcli project info --project ./acme
```

`--project` can be placed on any command. If omitted, `burpcli` uses
`$BURPCLI_PROJECT`, the project selected with `burpcli project use`, or `./.burpcli`.

Set a scope so accidental out-of-scope traffic is refused:

```console
$ burpcli --project ./acme scope add 'https://example.test/*'
$ burpcli --project ./acme scope check 'https://example.test/login'
https://example.test/login is in scope
```

Patterns support `*` and `?`. A bare host (`example.test`) matches that host on any
scheme and path. Use `scope add --exclude` for exclusions. An empty include list allows
everything; a scan adds the target's host automatically when no patterns exist.

## 3. Send a request

```console
$ burpcli --project ./acme repeater --url 'https://example.test/' --headers-only
HTTP/1.1 200 OK
...
```

Build requests with `--method`, `--header 'Name: value'` and `--data`, load raw
requests from disk with `--file`, or replay one from history with
`--history <id>`. Responses are saved to history unless `--no-save` is given.

## 4. Start the proxy

```console
$ burpcli --project ./acme proxy --port 8080
burpcli proxy listening on http://127.0.0.1:8080
project : ./acme
mode    : HTTP + CONNECT tunnel
```

Point a browser or CLI client at `http://127.0.0.1:8080`:

```console
$ curl -x http://127.0.0.1:8080 http://example.test/
```

HTTPS is tunnelled but not visible. To intercept it, generate and trust the project CA:

```console
$ burpcli --project ./acme ca export --output ./acme/ca/burpcli-ca.pem
$ burpcli --project ./acme proxy --port 8080 --mitm
```

Install `burpcli-ca.pem` in your browser or operating system trust store, then browse.
See [proxy-mitm.md](proxy-mitm.md) for details and cautions.

While the proxy runs:

- `burpcli history list --project ./acme` shows captured traffic.
- `burpcli history show <id> --project ./acme` prints a full request/response.
- `burpcli session set-cookie example.test sid abc123 --project ./acme` gives every
  proxied request that cookie.
- `burpcli session header 'X-Test: 1' --project ./acme` adds a static header.
- `burpcli session rule 'old' 'new' --project ./acme` rewrites request text.

Use `--intercept` to pause each exchange on the console. Press Enter or type `f` to
forward, `d` to drop, or `e` to edit the message in `$EDITOR`.

## 5. Scan

```console
$ burpcli --project ./acme scan 'https://example.test/search?q=hello' \
    --check xss --check sqli --point query --save-evidence
```

Omit `--check` to run every applicable check. Useful options:

| Option | Effect |
| --- | --- |
| `--check` / `--skip` | Select active checks (repeatable) |
| `--list-checks` | Print check names and descriptions |
| `--point` | Limit insertion points (repeatable: `query`, `form`, `json`, `cookie`, `header`, `path`) |
| `--passive` | Passive checks only |
| `--crawl-depth N` | Crawl N levels and scan each page |
| `--timing` | Enable time-based SQLi/command-injection probes |
| `--oob local` | Start an OOB listener for SSRF/XXE |
| `--format` / `--output` | Render a report immediately |
| `--fail-on high` | Non-zero exit when a finding is at or above the severity |

Results are appended to `issues.jsonl` and shown in the summary. Screenshots of
requests/responses are retained as base64 when `--save-evidence` is used.

## 6. Report

```console
$ burpcli --project ./acme report --stats
$ burpcli --project ./acme report --format markdown --output reports/acme.md
$ burpcli --project ./acme report --format burp-xml --output reports/acme.xml
$ burpcli --project ./acme report --format sarif --output reports/acme.sarif
```

Formats: `table` (default, to stdout), `json`, `html`, `burp-xml`, `sarif` and
`markdown`. `--min-severity` filters, `--include-evidence` embeds captured messages,
and `--title` sets the report title.

## 7. Attack with the intruder

Copy a request into a template and mark insertion points with `§`:

```console
$ burpcli --project ./acme intruder \
    --url 'https://example.test/login' \
    --data 'user=§admin§&pass=§pw§' \
    --attack cluster-bomb \
    --payload 'list:admin,root' \
    --payload 'list:admin,password' \
    --grep 'Welcome' \
    --extract 'token=session=([a-f0-9]+)' \
    --show 0
```

`--wrap hello` wraps an existing substring in markers when building from a URL. See
[intruder.md](intruder.md) for attack semantics, payload sources and processors.

## 8. Out-of-band callbacks

Start the collaborator locally:

```console
$ burpcli --project ./acme oob start --port 9000 --public-url http://127.0.0.1:9000
$ burpcli --project ./acme oob payload
http://127.0.0.1:9000/oob/<token>
```

`scan --oob local` starts its own listener and injects unique callback URLs for SSRF
and XXE checks. For targets that cannot reach your machine, expose the listener through
a tunnel or start the daemon on a public host and pass its base URL to `--oob`.

Poll recorded interactions with `burpcli oob poll`, or watch the JSONL event log in
`<project>/oob/events.jsonl`.

## 9. Extend with plugins

```console
$ burpcli --project ./acme plugin install-demo
$ burpcli --project ./acme plugin list
$ burpcli --project ./acme plugin test demo
```

A plugin is any executable or script that reads one JSON object per invocation from
stdin and writes one JSON object to stdout. Hooks are `request`, `response` and
`passive`. See [plugins.md](plugins.md) for the manifest and message schema.

## 10. Clean up

```console
$ burpcli --project ./acme history clear --yes
$ burpcli --project ./acme sitemap clear
```

Delete the whole project directory when you are done. Never leave a trusted project CA
installed after an engagement.
