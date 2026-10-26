# Out-of-band collaborator

The OOB collaborator gives SSRF, XXE and other blind checks a unique URL and records
any HTTP interaction with it. It is the equivalent of a Burp Collaborator server, with
one important difference: it is HTTP-only and does not run a DNS server.

```console
$ burpcli --project ./acme oob start
OOB collaborator running
url    : http://127.0.0.1:53142
bind   : 127.0.0.1:53142
pid    : 24188
control: 9f2c...            # 24-character control token
events : ./acme/oob/events.jsonl
```

`start` daemonises by default. The child is the same binary running a hidden
`__oob-serve` command, detached from your terminal. Use `--foreground` to keep it
attached, or pass `--bind 0.0.0.0 --port 8080 --public-url https://oob.example.test`
when the target must reach it over the network.

| Option | Default | Meaning |
| --- | --- | --- |
| `--bind` | `127.0.0.1` | Listener address. Use `0.0.0.0` for lab networks. |
| `--port` | `0` | Ephemeral port. Pin a port if you configure firewalls or a reverse proxy. |
| `--public-url` | derived | Base URL placed in payloads. **Required** when binding to `0.0.0.0` for a remote target, because the derived URL uses `127.0.0.1`. |
| `--foreground` | off | Do not daemonise. |
| `--json` | off | Print state as JSON. |

Starting again while a healthy daemon is running returns the existing daemon and
ignores new bind/port/public-URL flags. Stop it first if you need to change them.
A stale `state.json` is removed automatically when its process no longer answers.

## Using it

Generate a callback URL:

```console
$ burpcli --project ./acme oob payload
token: 4f9a1c7e2b8d0356
url  : http://127.0.0.1:53142/oob/4f9a1c7e2b8d0356
```

Send that URL to the target (for example as a `url=` parameter), then poll:

```console
$ burpcli --project ./acme oob poll
$ burpcli --project ./acme oob poll --token 4f9a1c7e2b8d0356 --json
$ burpcli --project ./acme oob status
$ burpcli --project ./acme oob clear
$ burpcli --project ./acme oob stop
```

`poll` reads `<project>/oob/events.jsonl`; it works even while the daemon is running.
`clear` truncates that file. `stop` calls the control endpoint and waits for the health
check to fail. `status` prints the recorded daemon state and whether it answers.

`oob url` prints the callback base URL from the running daemon. `oob payload
--base-url URL` generates a URL without requiring a local daemon, which is useful with
an external collaborator.

## Scanner integration

Active SSRF and XXE checks use an `OobProvider`:

```console
# In-process listener, ephemeral port, logs to <project>/oob/events.jsonl.
$ burpcli scan 'https://app.test/' --check ssrf --check xxe --oob local

# Use an already-running collaborator (local or remote).
$ burpcli scan 'https://app.test/' --check ssrf --check xxe \
    --oob http://127.0.0.1:53142
```

`--oob local` is not the daemon. It starts an ephemeral listener inside the scan
process for the duration of the scan, prints its base URL, and shuts it down at the
end. The events are still appended to `events.jsonl`, but the listener is gone once the
scan finishes. Use the daemon and pass its URL when you want to receive callbacks after
the scan, or when several tools share one collaborator.

`--oob off` or `--oob none` disables OOB. Omitting `--oob` also leaves SSRF/XXE
disabled; those checks silently do nothing rather than inventing callbacks.

The SSRF and XXE checks create a fresh 16-character token for every probe, inject a
URL of the form `<base>/oob/<token>`, and wait up to **4 seconds** for any interaction
with that token before moving on. A slow target or a proxy that buffers callbacks can
therefore produce a false negative. Run OOB checks with a low concurrency when timing
matters.

## What gets recorded

Each interaction stores:

```json
{
  "ts": "2026-10-26T12:34:56Z",
  "token": "4f9a1c7e2b8d0356",
  "method": "GET",
  "path": "/oob/4f9a1c7e2b8d0356",
  "query": "data=exfiltrated",
  "host": "127.0.0.1:53142",
  "remote": "10.0.0.5:49812",
  "headers": [["User-Agent", "curl/8.5.0"]],
  "body": ""
}
```

The token is extracted from `/oob/<token>`, then from a `token` query parameter, then
from the `Host` header, and finally from the path itself. This means arbitrary blind
callbacks (not just the generated ones) are recorded; filter with `poll --token` or
inspect the JSON.

Request bodies are read up to **1 MiB** and stored as UTF-8 with lossy replacement.
Headers are stored verbatim. Do not send credentials to a collaborator you do not
control.

## Remote and public deployment

To receive callbacks from a target on another network:

```console
$ burpcli --project ./acme oob start \
    --bind 0.0.0.0 --port 8080 \
    --public-url https://oob.example.test
$ burpcli scan 'https://target.test/' --check ssrf --oob https://oob.example.test
```

Requirements:

1. The target must be able to resolve and reach `oob.example.test:443`.
2. TLS termination is your responsibility. The collaborator speaks plain HTTP; put it
   behind a reverse proxy such as Caddy or nginx for HTTPS.
3. The reverse proxy must preserve the path (`/oob/<token>`) and forward request
   bodies. Host rewriting does not matter for `/oob/` URLs because the token is in the
   path.
4. Your scanning machine must reach the same base URL to poll. `RemoteOob` calls
   `<base>/__burpcli/poll?token=<token>` every 200 ms.

Firewalls, NAT and egress filtering are the usual reasons a callback never arrives.
Test with `curl https://oob.example.test/oob/test123` and confirm it appears in
`oob poll`.

## Management API

The listener has three management endpoints:

| Endpoint | Auth | Behaviour |
| --- | --- | --- |
| `GET /__burpcli/health` | none | Returns `{"ok":true}`. Used for liveness checks. |
| `GET /__burpcli/poll[?token=T]` | none | Returns a JSON array of interactions, optionally filtered by token. |
| `GET /__burpcli/shutdown?token=CONTROL` | control token | Stops the daemon. Wrong/missing token returns `403`. |

The control token is 24 random characters, stored in `<project>/oob/state.json` and
printed by `oob start`. It is **not** the same as a callback token.

There is no authentication on `health` or `poll`. Anyone who can reach the port can
read every recorded interaction and inject fake ones. Bind to `127.0.0.1` unless you
have intentionally exposed it, and never expose the management API to the internet
without an authenticating proxy.

## Files

| Path | Contents |
| --- | --- |
| `<project>/oob/state.json` | PID, bind address, port, base URL, control token, start time. |
| `<project>/oob/events.jsonl` | One JSON interaction per line, append-only until `clear`. |

The daemon writes the state file after binding, then removes it on shutdown. If the
process is killed, the next `start` detects the dead port and replaces the state file.
`stop` sends the control request to loopback, so it works even if `--public-url`
points elsewhere.

## Limitations

- **HTTP only.** No DNS, SMTP or generic TCP callbacks. Blind SSRF that only performs
  a DNS lookup, or XXE that only resolves a DNS name, will not be detected.
- No TLS listener. Terminate TLS in a reverse proxy.
- No payload encryption, signed tokens or per-token expiry. Tokens are random, not
  secret.
- No automatic interaction-to-finding correlation outside the SSRF/XXE checks; inspect
  `poll` manually for other blind bugs.
- The listener reads one request per connection and does not support keep-alive,
  chunked uploads or HTTP/2.
- No rate limiting. A public deployment can be flooded; put it behind a proxy with
  limits.
- Event history grows without bound until `oob clear`.
