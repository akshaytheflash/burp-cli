# Security and legal notes

`burpcli` is an offensive security testing tool. It sends crafted requests, can
impersonate TLS servers, records credentials, and can expose an HTTP listener. Use it
only where you have explicit permission.

This page is practical guidance, not legal advice. Laws, contracts and disclosure norms
vary by jurisdiction and by client. Consult your legal or compliance team before
testing.

## Authorization

Before sending a single probe:

1. **Get written authorization.** Identify the exact hosts, paths, accounts, test
   windows and allowed techniques. "We have a bug bounty" is not blanket permission:
   read the programme scope and rules.
2. **Stay inside scope.** Put included hosts in the project scope and use
   `--only-in-scope` on the proxy. Scope matching is a convenience, not an enforcement
   boundary: redirects, plugins and manual requests can still leave it.
3. **Respect exclusions.** Third-party services, payment processors, identity providers
   and shared infrastructure are commonly excluded even when they are linked from the
   target.
4. **Do not test production data you do not need.** Prefer staging, test accounts and
   synthetic records. Stop if you encounter real personal data, secrets or customer
   content.
5. **Agree on escalation.** Know who to call for a critical finding, an outage, or an
   accidental data exposure, and how to stop the test quickly.

Unauthorized access or impairment of a system is a crime in many jurisdictions, even
if the request is "just a GET" or the vulnerability is obvious.

## Safe operating practices

- **Rate-limit everything.** Use `--delay`, low `--concurrency` and `--max-urls`.
  Scanners and intruders can generate thousands of requests in seconds.
- **Avoid destructive payloads.** The built-in checks are detectors, not exploit
  chains, but command injection and file-inclusion probes can still trigger side
  effects on poorly written applications. Never point an intruder at delete, transfer
  or password-reset endpoints without a plan.
- **Do not run timing checks against fragile systems.** `--timing` deliberately sleeps
  and can hold worker threads.
- **Watch shared infrastructure.** A WAF, CDN or load balancer may rate-limit or block
  the client IP, affecting other users.
- **Keep an activity log.** Project history, issue timestamps and terminal transcripts
  help you reconstruct exactly what was sent if a client asks.

## Data handling

`burpcli` projects are plain files. Treat the whole directory as sensitive:

| Data | Location | Risk |
| --- | --- | --- |
| Full requests/responses | `history.jsonl`, `issues.jsonl`, sitemap | Cookies, tokens, PII, internal URLs. |
| Session state | `session.json` | Live cookies, static auth headers, macros. |
| CA private key | `ca/burpcli-ca.key` | Can impersonate any host to clients that trust the CA. |
| OOB interactions | `oob/events.jsonl` | Callback bodies, source IPs, exfiltrated data. |
| Plugin code and output | `plugins/` | Arbitrary code and whatever it reads. |

Recommendations:

- Encrypt the disk or the project directory; restrict permissions to your user.
- Do not commit projects, history, issues or the CA key to source control. The
  repository's `.gitignore` excludes common project artefacts, but verify before
  pushing.
- Delete project data and uninstall the CA when the engagement ends.
- Redact evidence before sharing reports. `--save-evidence` stores full request and
  response bodies; omit it for reports that leave your control.
- Rotate any credential that was captured, even if you believe it was a test account.

## The interception CA

`--mitm` makes `burpcli` a man-in-the-middle for clients that trust the project CA. The
CA key is unencrypted PEM.

- Generate a separate CA per engagement or project; do not reuse a personal CA.
- Install it only in a browser, emulator or test device you control.
- Remove it from the trust store when done. On Windows:
  `certutil -delstore -user Root "<CA common name>"`. On macOS, delete it from
  Keychain Access. In Firefox, delete it from the Authorities list.
- Verify the SHA-256 fingerprint out of band before trusting a CA file.
- Never install the CA on a shared workstation, a CI runner used for other work, or a
  device you do not own.
- Certificate pinning and Android network-security-config restrictions are not bypassed
  by installing a CA.

## The OOB listener

`oob start --bind 0.0.0.0` exposes an unauthenticated HTTP service:

- `/__burpcli/health` and `/__burpcli/poll` have no authentication. Anyone who can
  reach the port can read all interactions and inject fake ones.
- The control token protects only the shutdown endpoint. It is stored in
  `state.json`.
- Bind to loopback by default. If a remote target must call back, expose only the
  callback path through a reverse proxy with TLS, access controls and rate limits, and
  shut the listener down after the test.
- Callback data may include credentials or customer data sent by the target. Handle it
  like any other engagement evidence.

## Plugins and supply chain

Plugins are arbitrary code with your privileges.

- Review every plugin before enabling it. There is no signature or sandbox.
- Pin plugin versions and record their hashes if you need reproducibility.
- Do not run plugins from an untrusted project directory. Opening a project does not
  execute plugins while `plugins.enabled = false`, but the code is still on disk and a
  single `plugin enable` changes that.
- Plugin output is untrusted: it can forge findings, rewrite traffic and make network
  requests of its own.

## Reports and disclosure

- Separate confirmed findings from scanner output. The scanner reports candidates;
  validate them before calling them vulnerabilities.
- Include reproduction steps, affected assets, impact, evidence and remediation.
- Redact secrets, personal data and unrelated internal hostnames.
- Follow the client's disclosure timeline and channel. Do not publish, tweet or post
  screenshots before you have written approval.
- If you find evidence of an active compromise or a threat to life/safety, escalate
  immediately through the agreed channel rather than waiting for the report.

## Legal summary

You are responsible for what you send and for the data you retain. The authors and
contributors of `burpcli` grant no permission to test any system, provide no warranty,
and accept no liability for misuse or damage. See [LICENSE](../LICENSE).
