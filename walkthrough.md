# Splice — Walkthrough

A start-to-finish guide to running **Splice**, the authorization-enforced
intercepting proxy written in the Mutant language. Covers building, running,
trusting the CA, wiring a browser, both topologies, every feature, and where the
output lands.

> **Authorization only.** Splice is a MITM interception tool. Run it exclusively
> against hosts you are authorized to test. Scope is enforced in
> `policy/scope.rego`; everything else is denied at the proxy.

---

## 0. What Splice is (30 seconds)

An HTTP/HTTPS intercepting proxy — the Burp/ZAP/mitmproxy slot — that adds three
things those tools leave advisory or bolt on:

1. **Enforced scope** — every request is evaluated against `policy/scope.rego`
   (OPA/Rego) *before* it can egress. Out-of-scope hosts are unreachable, and
   every allow/deny is traceable (a compliance artifact).
2. **A real graph site-map** — endpoints, params, and findings become nodes/edges
   in an embedded graph DB; `db_shortest_path` chains an entry point to a sink.
3. **Sandboxed, hot-loadable Lua check plugins** — Burp-extension power, no JVM.

Plus: match/replace, secret-hunting, concurrency, WebSocket interception,
streaming bodies, an on-disk audit + findings trail, and a built-in report page.

---

## 1. Prerequisites

- The Mutant `dev-sec` runtime built as `mutant.exe`:
  ```sh
  cd "D:/Security Research/mutant" && go build -o mutant.exe .
  ```
- (Optional) Burp Suite if you want the `Browser → Splice → Burp → target` chain.

---

## 2. Compile and run

Splice reads its config path from the `CONFIG_PATH` constant at the top of
`splice.mut` (set to the absolute path of `splice.config.json`). Compile the
source to bytecode, then run the bytecode:

```sh
cd "D:/Security Research/mutant"
mutant.exe "D:/Security Research/splice/splice.mut" --password test        # -> splice.mu
mutant.exe "D:/Security Research/splice/splice.mu"  --password test --compat
```

Use **`--compat`** (not `--dev`): the security machinery stays active, but the
WSL/hypervisor anti-sandbox check is advisory instead of fatal on this box.
First start takes ~15–30 s (the compiled bytecode is decrypted with Argon2id by
design); after that it's fast.

On startup Splice prints its CA and:
```
proxy listening on 127.0.0.1:8123 (concurrent). Scope enforced by policy/scope.rego.
```

---

## 3. Trust Splice's CA (one time)

Splice terminates TLS with a per-host leaf minted from its own CA. Your client
must trust that CA (`ca/splice-ca.pem`, generated + reused across runs).

- **Firefox** (own store): `Settings → Privacy & Security → Certificates → View
  Certificates → Authorities → Import…` → pick `ca/splice-ca.pem` → tick "Trust to
  identify websites".
- **Chrome / Brave / Edge** (Windows store): run it yourself (changes a security
  setting):
  ```powershell
  certutil -addstore -user Root "D:\Security Research\splice\ca\splice-ca.pem"
  ```
  then fully restart the browser.

Remove when done: `certutil -delstore -user Root "Splice Intercept CA"`, and
delete `ca/splice-ca.pem` / `-key.pem` to rotate.

---

## 4. Point your browser at Splice

Set the browser's HTTP **and** HTTPS proxy to `127.0.0.1:8123` (Splice's bind).
A proxy switcher like FoxyProxy makes this a one-click toggle.

Browse an in-scope host → the page loads and Splice logs the intercept. Browse an
out-of-scope host → you get Splice's `403` block page.

---

## 5. Two topologies

### A. Standalone (Splice → target)
`splice.config.json`: `"upstream_proxy": ""`. Splice dials origins directly.
Simplest; nothing else required.

### B. Chained in front of Burp (recommended)  — `Browser → Splice → Burp → target`
`splice.config.json`:
```json
"bind": "127.0.0.1:8123",
"upstream_proxy": "127.0.0.1:8080",
"upstream_tls_insecure": true
```
Splice enforces scope + records the site-map/findings **first**, then forwards to
Burp for interactive work (Repeater/Intruder/history). Out-of-scope hosts are
denied at Splice and never reach Burp. Only Splice's CA needs to be in the browser
(Splice accepts Burp's leaf via `upstream_tls_insecure`).

> **Burp Intercept note:** keep Burp **Intercept OFF** for browsing — Intercept
> holds *every* request until you Forward it, so pages hang. Burp's Proxy → HTTP
> history still captures everything without holding. When you do use Intercept,
> Splice waits up to `intercept_timeout_ms` (default 60 s) for you to Forward.

---

## 6. What you get (outputs)

| Artifact | Where | What |
|----------|-------|------|
| **Audit trail** | `splice-audit.log` | one `ALLOW`/`DENY` line per request — the proof-of-scope artifact |
| **Findings** | `splice-findings.log` | one line per secret-hunt / plugin hit |
| **Report** | `http://splice.report/` (browse through the proxy) | live dashboard: graph size + decisions + findings |
| **Site-map graph** | in-memory (`db_*`) | hosts/endpoints/params/findings nodes + edges; queryable via `db_shortest_path` |
| **CA** | `ca/splice-ca.pem` | import once |

Console log per request shows `[allow]`/`[DENY]`, `[stream]`, `[response] … (Nms / bytes)`,
and `[finding] …`.

---

## 7. Customising an engagement

- **Scope (RoE)** — edit `policy/scope.rego`: `in_scope_hosts`, `allowed_methods`,
  `denied_path_prefixes`. This is the enforced, diffable Rules-of-Engagement file.
- **Checks** — drop a `.lua` file in `plugins/` and add it to the `plugins` array
  in the config. Contract: read `SPLICE_PHASE/METHOD/HOST/PATH/QUERY/STATUS/BODY/RAW`
  globals, return a JSON array of `{severity,title,detail}` (`"[]"` for none). Ships
  with `secret_leak`, `security_headers`, `reflected_input`.
- **Match/replace** — `matchreplace/rules.json`: Go RE2 regex over the outgoing
  request wire, applied in order. Ships with: pin User-Agent, inject
  `X-Splice-Tester`, strip `utm_*`, and strip `If-None-Match`/`If-Modified-Since`
  (so responses come back as full **200**s instead of **304**s — the plugins need a
  body to scan).

---

## 8. Config reference (`splice.config.json`)

| Key | Default | Meaning |
|-----|---------|---------|
| `mode` | `proxy` | `proxy` (live) or `selftest` (offline engine self-test, 14 assertions) |
| `root` | — | base dir for relative paths |
| `bind` | `127.0.0.1:8123` | Splice's listener |
| `policy_path` | `policy/scope.rego` | enforced scope |
| `matchreplace_path` | `matchreplace/rules.json` | match/replace rules |
| `plugins` | — | array of Lua plugin paths |
| `ca_cert_path` / `ca_key_path` | `ca/splice-ca.*` | persistent CA (generated once) |
| `audit_log` / `findings_log` | `splice-*.log` | on-disk trails |
| `upstream_proxy` | `""` | chain to a downstream proxy (Burp) or empty for direct |
| `upstream_tls_insecure` | `false` | accept the downstream proxy's MITM leaf (chain only) |
| `stream` | `true` | stream response bodies (no 32 MiB cap); `false` = buffered |
| `serial` | `false` | `true` = legacy one-connection-at-a-time loop |
| `connect_timeout_ms` | `8000` | upstream dial timeout |
| `upstream_timeout_ms` | `15000` | upstream read timeout (direct) |
| `intercept_timeout_ms` | `60000` | upstream read timeout when chained (patience for Burp Intercept) |

---

## 9. Feature checklist (what runs on live traffic)

- **Policy enforcement** — scope allow/deny with a traceable decision, fail-closed.
- **Graph site-map** — `record_flow` builds host/endpoint/param nodes + edges;
  `record_referer_edge` adds `links_to` from the `Referer` header (real nav chains).
- **Secret hunt + Lua plugins** — run on every response body.
- **Match/replace** — applied to every forwarded request.
- **Concurrency** — `net_serve` dispatches each connection to its own VM; requests
  are handled in parallel.
- **WebSocket interception** — after the Upgrade, frames are relayed full-duplex and
  logged (a reverse-pump goroutine handles server→client).
- **Streaming** — bodies pump through in chunks with no whole-body buffer.
- **Timing** — per-request upstream latency is logged.

---

## 10. Verify the engine offline

Set `"mode": "selftest"` in the config and run the compiled `.mu`: it drives the
whole engine (policy, match/replace, graph, secret-hunt, plugins, attack-path)
against synthetic flows with no sockets and asserts every outcome:

```
=== Self-test complete: 14 passed, 0 failed ===
RESULT: OK
```

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Browser "connection is not private" / untrusted root | Splice's CA isn't trusted — redo §3 for that browser (Firefox has its own store). |
| Pages hang with Burp **Intercept ON** | Expected — Intercept holds every request. Keep it OFF for browsing; use HTTP history for visibility. |
| `502 upstream/gateway error` when chained | Burp isn't forwarding — check it's listening on 8080 and Intercept is off (or you forwarded the request). |
| Everything returns 200 incl. out-of-scope | You're hitting Burp (8080) directly, not Splice — point the browser at **8123**. |
| Getting **304 Not Modified**, want the body | The `strip-if-none-match` / `strip-if-modified-since` rules force full 200s — make sure they're in `rules.json` and restart Splice. |
| `sandbox detected, execution halted` | You ran without `--compat`. On a VM/WSL box use `--compat`; on bare metal, no flags = full enforcement. |
| Very slow first request | Argon2id bytecode decrypt on startup (~15–30 s). Only the first bind is slow. |
