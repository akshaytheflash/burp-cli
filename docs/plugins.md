# Plugins

`burpcli` can run external programs as plugins. A plugin is any executable or script
that reads one JSON object from stdin and writes one JSON object to stdout. Plugins can
rewrite requests and responses in the proxy, drop traffic, and contribute findings to
the proxy history or scanner.

This is deliberately language-agnostic: Python, Go, Node, a shell script or a compiled
binary all work. There is no plugin ABI and no shared library loading.

## Managing plugins

```console
$ burpcli plugin install-demo
$ burpcli plugin list
$ burpcli plugin list --json
$ burpcli plugin test demo
$ burpcli plugin disable
$ burpcli plugin enable
$ burpcli plugin remove demo
```

Plugins live in `<project>/plugins/`, one directory per plugin:

```text
<project>/plugins/
  my-plugin/
    plugin.toml
    plugin.py
    wordlist.txt
```

The loader is non-recursive. It reads every `plugin.toml` inside a direct child
directory, and also accepts a top-level `*.toml` manifest. A manifest must contain a
non-empty `name` and `command`; invalid manifests cause `plugin list` and proxy/scan
startup to fail loudly rather than silently skipping code.

`install-demo` also sets `plugins.enabled = true` in `project.toml`. Other commands only
report or change state; they never install code from the network.

## Manifest

```toml
name = "header-audit"
description = "Flags missing cache-control on authenticated responses"
command = "python3 plugin.py --strict"
hooks = ["response", "passive"]
enabled = true
timeout_ms = 3000
```

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `name` | yes | - | Unique identifier; used in messages and issue attribution. |
| `description` | no | empty | Shown by `plugin list`. |
| `command` | yes | - | Executable plus arguments. Split like a shell command line, but **without** a shell. |
| `hooks` | no | `request`, `response`, `passive` | Which hooks the plugin handles. Unknown names are ignored. |
| `enabled` | no | `true` | Disabled plugins are listed but never invoked. |
| `timeout_ms` | no | project `plugins.timeout_ms` (5000) | Per-invocation limit. |

Because `command` is split without a shell, pipes, `&&`, redirects and `$VAR`
expansion do not work. Write a wrapper script if you need them. Quoted paths with
spaces are supported; on Windows use forward slashes or a quoted path.

The working directory for every invocation is the plugin's own directory, not the
project root and not the current directory. Relative paths in the manifest and in your
script therefore resolve next to `plugin.toml`.

## Protocol

One invocation handles one message:

1. `burpcli` starts the command as a subprocess.
2. It writes a single JSON object followed by `\n` to stdin.
3. The plugin writes a single JSON object followed by `\n` to stdout.
4. `burpcli` reads the first line, kills the process, and applies the result.

The process is killed after replying even if it would have kept running. It is also
killed on timeout. Anything the plugin writes to stderr is included in the error text
when the reply is empty or invalid. Extra lines on stdout after the first are ignored.

### Input

```json
{
  "hook": "response",
  "request": {
    "method": "GET",
    "target": "/account",
    "version": "HTTP/1.1",
    "headers": [{"name": "Host", "value": "app.test"}],
    "body_b64": "",
    "scheme": "https",
    "url": "https://app.test/account"
  },
  "response": {
    "version": "HTTP/1.1",
    "status": 200,
    "reason": "OK",
    "headers": [{"name": "Content-Type", "value": "text/html"}],
    "body_b64": "PGh0bWw+"
  },
  "project": "acme"
}
```

- `hook` is `request`, `response` or `passive`.
- `request` is present for every hook. `response` is present for `response` and
  `passive`, and absent for `request`.
- `body_b64` is standard base64 (empty string for an empty body). Headers are an array
  of `{ "name", "value" }` objects, preserving order and duplicates.
- `url` is informational; `target` is the origin-form request target.
- `project` is the project name, omitted when no project is open.

### Output

```json
{
  "action": "continue",
  "request": { "...": "optional replacement" },
  "response": { "...": "optional replacement" },
  "issues": [
    {
      "check": "cache-control",
      "title": "Authenticated response is cacheable",
      "severity": "low",
      "confidence": "firm",
      "detail": "The response sets a session cookie without Cache-Control: no-store.",
      "evidence": "Set-Cookie: sid=...",
      "remediation": "Send Cache-Control: no-store on authenticated responses.",
      "parameter": null,
      "cwe": 524
    }
  ]
}
```

- `action` is `continue` (default) or `drop`. Only request/response hooks can drop.
- `request` replaces the current request in a request hook. A replacement is parsed as
  a complete request; invalid replacements are reported and the previous message is
  kept.
- `response` replaces the current response in a response hook. It is ignored in a
  passive hook.
- `issues` are converted to findings. Unknown fields are ignored.

An empty or invalid output object is a plugin error, not a silent success. Errors are
reported in proxy logs and scan errors; they do not crash the proxy. A plugin that
hangs delays that one exchange until its timeout.

### Issue mapping

| Field | Behaviour |
| --- | --- |
| `check` | Check identifier; defaults to the plugin name. Combined with method, URL and parameter for de-duplication. |
| `title` | Defaults to `Plugin finding`. |
| `severity` | `high`/`critical` -> High, `medium`/`med` -> Medium, `low` -> Low, anything else -> Info. |
| `confidence` | `certain` -> Certain, `tentative` -> Tentative, otherwise Firm. |
| `detail`, `evidence`, `remediation`, `parameter`, `cwe` | Copied to the finding when present. |

Every plugin issue embeds the request that triggered it. Response evidence is not
attached automatically, so include the relevant snippet in `evidence`.

## Hooks

| Hook | When it runs | Can modify | Can drop |
| --- | --- | --- | --- |
| `request` | Proxy, before forwarding. | Request. | Request. |
| `response` | Proxy, after the upstream response. | Response. | Response. |
| `passive` | Scanner, once per scanned page. | Nothing. | Nothing. |

- **Proxy:** request hooks run after scope/header/rule handling and before interactive
  interception. Response hooks run after rules and before interactive interception.
  Findings are appended to `issues.jsonl`.
- **Scanner:** passive hooks run after the built-in passive checks for every scanned or
  crawled page. Their issues are de-duplicated with the built-in findings and stored in
  the same scan result. Response hooks are *not* run by the scanner.
- **`plugin test`:** starts the plugin with a synthetic `GET /plugin-test` request using
  the `request` hook and prints the raw JSON reply. It does not validate the response
  schema beyond the normal invocation path.

Passive hooks are read-only by design: returning `action: "drop"` or a replacement
message has no effect. Use a response hook for traffic modification.

## Example plugin

A minimal Python plugin that adds a header and reports a finding when a marker is
present:

```python
#!/usr/bin/env python3
import base64, json, sys

line = sys.stdin.readline()
if not line.strip():
    sys.exit(0)

msg = json.loads(line)
out = {"action": "continue"}

response = msg.get("response")
if response is not None:
    if msg["hook"] == "response":
        response["headers"].append({"name": "X-Reviewed-By", "value": "audit-plugin"})
        out["response"] = response

    body = base64.b64decode(response.get("body_b64") or "").decode("utf-8", "replace")
    if "TODO_SECURITY" in body:
        out["issues"] = [{
            "check": "todo-security",
            "title": "Security TODO left in a response",
            "severity": "low",
            "confidence": "certain",
            "detail": "A security marker was found in the response body.",
            "evidence": "TODO_SECURITY",
            "remediation": "Complete the security work before shipping."
        }]

print(json.dumps(out), flush=True)
```

Install it as `<project>/plugins/audit/plugin.toml` with
`command = "python3 plugin.py"` and a copy of the script next to it, then run
`burpcli plugin test audit`.

The built-in demo plugin (`burpcli plugin install-demo`, hidden command
`__plugin-demo`) implements exactly this shape: it adds `X-Burpcli-Plugin: demo` to
responses and emits a Low `plugin-demo` finding when the body contains the string
`plugin-demo`.

## Failure handling

| Situation | Result |
| --- | --- |
| Command cannot be started | Plugin error; original message forwarded unchanged. |
| Non-zero exit with no stdout | Plugin error including stderr. |
| Invalid JSON or wrong shape | Plugin error including a truncated reply. |
| Timeout | Process killed; plugin error; message forwarded unchanged. |
| Invalid request/response replacement | Error; previous message kept. |
| Drop in a request hook | Later request plugins are skipped; proxy returns `403` and records a `dropped` entry. |
| Drop in a response hook | Later response plugins are skipped; proxy substitutes `403`. |

A single plugin failure never aborts the proxy or the scan. `plugin test` does return an
error, which makes it suitable for CI smoke tests.

## Security

Plugins are arbitrary code running with your user privileges. There is no sandbox,
capability model, signature check or network isolation.

- Install only plugins you have reviewed.
- Treat a plugin directory as executable content: cloning a project does not run
  plugins until `plugins.enabled = true`, but the code is still present.
- Plugin output is untrusted input: it can rewrite requests, exfiltrate data through
  its own network access, and forge findings. The terminal rendering is not a security
  boundary.
- Timeouts kill the child process, but a plugin can spawn its own detached processes.
- The plugin sees full request/response bodies, cookies and authorization headers.

## Limitations

- One process per invocation, so per-request latency includes process startup. Keep
  scripts small or use a compiled helper.
- No shared state between invocations; persist state in the plugin directory or an
  external service.
- No async/concurrent hook execution in the proxy: hooks are synchronous and serialised
  per exchange.
- No plugin ordering control beyond alphabetical `name` order.
- The scanner only invokes the passive hook; it does not let plugins generate active
  probes.
- HTTP/1.1 messages only; HTTP/2 pseudo-headers are not represented.
- No hot reload: restart the proxy or re-run the scan after changing a manifest or
  script.
