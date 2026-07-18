# Using Splice with your browser and Burp Suite

This guide sets up Splice as an **enforced-scope gate in front of Burp** for an
authorized engagement against `whokilledtulpa.com`, and shows the exact browser
and Burp configuration. It is written for the machine this was built on (Windows,
Burp already listening on `127.0.0.1:8080`), but the steps generalize.

> **Authorization.** Only run this against hosts you are authorized to test. The
> shipped scope (`policy/scope.rego`) is limited to `whokilledtulpa.com` and
> `www.whokilledtulpa.com`; every other host is denied at the proxy.

---

## 1. The topology

The recommended chain — the one you asked for — puts Splice first so it enforces
scope and records the site-map/findings **before** anything reaches Burp:

```
   Browser  ──▶  Splice (127.0.0.1:8123)  ──▶  Burp (127.0.0.1:8080)  ──▶  target
                 │  enforce scope (scope.rego)        │  your usual
                 │  audit log + graph site-map        │  Repeater / Intruder /
                 │  secret-hunt + Lua check plugins    │  history / manual work
                 │  match/replace on requests          │
```

- The **browser** trusts **Splice's** CA and points its proxy at **Splice:8123**.
- **Splice** decrypts, enforces scope (out-of-scope hosts get `403` and never
  reach Burp), records the flow, runs checks, then **chains to Burp** via
  `upstream_proxy`.
- **Burp** does its normal interception/Repeater/etc. against the target.

An out-of-scope request dies at Splice:

```
Browser → https://example.com  →  Splice: 403 Forbidden   (Burp never sees it)
```

There is also an inverted topology (Burp first, Splice as Burp's *upstream
proxy*): `Browser → Burp:8080 → Splice:8123 → target`. Use that if you want Burp's
UI on everything and Splice purely as the egress scope-gate. See §6.

---

## 2. Prerequisites

- The Mutant `dev-sec` runtime built as `mutant.exe`:
  ```sh
  cd mutant/ && go build -o mutant.exe .
  ```
- Burp Suite running with its Proxy listener on `127.0.0.1:8080` (default).
- `splice.config.json` set for the chain (already done on this machine):
  ```json
  "bind": "127.0.0.1:8123",
  "upstream_proxy": "127.0.0.1:8080",
  "upstream_tls_insecure": true
  ```
  `upstream_tls_insecure` lets Splice accept Burp's own MITM leaf on the hop to
  Burp. Set `upstream_proxy` to `""` to run Splice standalone (direct to target).

---

## 3. Start Splice

Compile once, then run. Use `--compat` (not `--dev`) so the security machinery
stays active but the WSL/hypervisor sandbox detection on this box is advisory
rather than fatal:

```sh
mutant.exe splice.mut --password test        # -> splice.mu
mutant.exe splice.mu --password test --compat
```

On first run Splice generates a CA and writes it to
`splice/ca/splice-ca.pem` (and `-key.pem`). It reuses that CA
on later runs, so you import it **once**. Splice then prints the CA and:

```
proxy listening on 127.0.0.1:8123 (set as HTTP+HTTPS proxy). Scope enforced by policy/scope.rego.
```

> First start takes ~15–30 s: the compiled bytecode is decrypted with Argon2id by
> design. Subsequent requests are fast.

---

## 4. Import Splice's CA (one time)

In the chain, your browser speaks TLS to **Splice**, so the browser must trust
**Splice's** CA (`ca/splice-ca.pem`). Splice accepts Burp's cert automatically via
`upstream_tls_insecure`, so you do **not** need Burp's CA in the browser for this
topology.

**Firefox** (uses its own store — simplest):
1. `Settings → Privacy & Security → Certificates → View Certificates…`
2. `Authorities` tab → `Import…` → choose `splice\ca\splice-ca.pem`
3. Tick **"Trust this CA to identify websites"** → OK.

**Chrome / Edge** (use the Windows Trusted Root store). Import it yourself — this
changes a system security setting, so do it manually rather than via a tool:
1. `Win+R` → `certmgr.msc`
2. `Trusted Root Certification Authorities → Certificates → All Tasks → Import…`
3. Select `splice-ca.pem`, finish the wizard, accept the warning.

Remove it when the engagement ends (delete it from the same store, and delete
`ca/splice-ca.pem` / `-key.pem` to rotate).

---

## 5. Point the browser at Splice

Set the browser's HTTP **and** HTTPS proxy to `127.0.0.1:8123`.

**Firefox:** `Settings → Network Settings → Manual proxy configuration`
- HTTP Proxy `127.0.0.1`  Port `8123`
- Tick **"Also use this proxy for HTTPS"**
- Clear "No proxy for" of `localhost`/`127.0.0.1` **only if** you need to test a
  local target; otherwise leave defaults.

**Chrome/Edge (Windows system proxy)** or use a proxy-switcher extension:
- `Settings → System → Open your computer's proxy settings → Manual proxy setup`
- Address `127.0.0.1`  Port `8123`.

Now browse `https://whokilledtulpa.com/`. The page loads normally; Splice logs the
intercept, and Burp's **Proxy → HTTP history** also shows the request (it came
through the chain). Browse `https://example.com` and you get Splice's
`403 Forbidden` block page — Burp never sees it.

---

## 6. Alternative: Splice behind Burp

If you would rather drive everything from Burp and use Splice only as the egress
scope-gate (`Browser → Burp:8080 → Splice:8123 → target`):

1. In Splice config set `"upstream_proxy": ""` (Splice dials origins directly).
2. In Burp: `Settings → Network → Connections → Upstream proxy servers → Add`
   - Destination host `*`
   - Proxy host `127.0.0.1`  Proxy port `8123`
3. Point the browser at Burp (`127.0.0.1:8080`) as usual, and import **both**
   Burp's CA and Splice's CA into the browser (traffic is re-encrypted at each
   hop).

Trade-off: here Burp sees out-of-scope hosts before Splice can deny them (Splice
still blocks egress, but Burp already logged the attempt). The §1 topology
(Splice first) is stricter and is the default in the shipped config.

---

## 7. Verify from the command line

`curl` on Windows uses Schannel, which **ignores `--cacert`** and checks the
Windows store — so for a quick CLI check use `-k` (skip client-side trust) rather
than fighting the trust chain:

```sh
# in-scope: intercepted and relayed, returns the real page
curl -k -x http://127.0.0.1:8123 https://whokilledtulpa.com/ -o nul -w "%{http_code}\n"     # 200

# out-of-scope: denied by Splice before egress
curl -k -x http://127.0.0.1:8123 https://example.com/ -o nul -w "%{http_code}\n"            # 000/403 (blocked)
```

The persisted audit trail is at `splice-audit.log`:

```
ALLOW CONNECT whokilledtulpa.com :: in scope
ALLOW GET whokilledtulpa.com/ :: in scope
DENY  CONNECT example.com :: out-of-scope host
```

---

## 8. What Splice found on whokilledtulpa.com

Live run through `Browser → Splice → Burp → whokilledtulpa.com`, from the
`security_headers.lua` plugin (verified against the real site):

| Severity | Finding |
|----------|---------|
| medium | Missing `Content-Security-Policy` |
| low | Missing `X-Frame-Options` |
| low | Missing `X-Content-Type-Options` |

Each is recorded as a node in the graph site-map, linked to the endpoint it was
seen on, so `db_shortest_path` can chain an entry point to a sensitive sink. Add
your own checks by dropping a `.lua` file in `plugins/` (see `docs/DESIGN.md §4`).

---

## 9. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Browser: "connection is not private" / untrusted root | Splice's CA isn't trusted. Re-do §4 for the browser you're using. Firefox has its own store separate from Windows. |
| `502` on in-scope HTTPS | Upstream unreachable. If chaining, confirm Burp is listening on 8080 and Burp **Intercept is OFF** (an intercepted request stalls the tunnel). Check the `[!] upstream connect failed` line in Splice's console. |
| Everything returns `200` incl. out-of-scope | You're hitting Burp (8080) directly, not Splice. Point the browser at **8123**. |
| Splice won't start / `listen failed` | Another process owns the bind port. Burp uses 8080; Splice uses 8123. Pick a free port in `bind`. |
| `sandbox detected, execution halted` | You ran without `--compat`. On a virtualized/WSL box the anti-sandbox check is fatal in full-secure mode; use `--compat` (security stays active, detection advisory). On a bare-metal deploy box, run with no flags for full enforcement. |
| First request very slow | Argon2id bytecode decrypt on startup (~15–30 s). Only the first bind is slow; requests after are fast. |
