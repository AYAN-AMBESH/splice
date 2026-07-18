# Splice

An **authorization-enforced intercepting proxy** — the Burp / ZAP / mitmproxy
slot — written entirely in the [Mutant](../mutant) language and running on the
`dev-sec` secure-networking runtime.

Splice is a MITM HTTP/HTTPS proxy for **authorized** security testing. What makes
it different from a general-purpose intercept proxy is that the things those tools
leave advisory or bolt on afterwards are native and load-bearing here:

1. **Scope is enforced policy, not a UI hint.** Every request is evaluated against
   [`policy/scope.rego`](policy/scope.rego) (OPA/Rego) *before* it can reach the
   forwarding path. An out-of-scope host is literally unreachable through the
   proxy, and every allow/deny is traceable (`policy_trace`) — a compliance
   artifact that proves you stayed inside the Rules of Engagement. In Burp, scope
   is advisory and one fat-fingered click puts you out of bounds.

2. **The site map is a real graph.** Endpoints, parameters, and findings become
   nodes and edges in an embedded graph DB (`db_*`). `db_shortest_path` answers
   *"what is the chain from an unauthenticated entry point to this sensitive
   sink?"* — instead of a flat tree plus a separate issue list you would have to
   correlate by hand.

3. **Checks are sandboxed, hot-loadable Lua plugins** ([`plugins/`](plugins)).
   Burp-extension power without the JVM; the signed core binary never changes when
   you add a check.

Match/replace, secret hunting, and session state come from the runtime's
`regex_*` / `cache_*` builtins.

## Why the Mutant substrate matters

The whole engagement proxy ships as **one signed, encrypted, cross-compiled
binary** you drop on a client box — no Python/Java/Node, no dependency tree,
tamper-evident and provenance-stamped. The policy that governs it is a
version-controlled file, not clicks in a GUI, so scope decisions are reviewable
and diffable like any other artifact.

## Layout

| Path | Purpose |
|------|---------|
| [`splice.mut`](splice.mut) | The tool: policy engine, graph site-map, secret hunt, plugin runner, match/replace, and the live proxy loop. |
| [`splice.config.json`](splice.config.json) | Runtime config: mode, bind address, paths, timeouts. |
| [`policy/scope.rego`](policy/scope.rego) | The enforced Rules of Engagement (in-scope hosts, allowed methods, denied paths). **Edit this per engagement.** |
| [`matchreplace/rules.json`](matchreplace/rules.json) | Burp-style match/replace rules (regex over the outgoing request wire). |
| [`plugins/*.lua`](plugins) | Hot-loadable check plugins (secret leak, missing security headers, reflected input). |
| `ca/splice-ca.pem` | Persistent CA (generated on first proxy run). Import once into your browser / Burp. |
| `splice-audit.log` | On-disk decision trail (one ALLOW/DENY line per request) — the proof-of-scope artifact. |
| [`docs/USING_WITH_BROWSER_AND_BURP.md`](docs/USING_WITH_BROWSER_AND_BURP.md) | **Step-by-step**: run Splice, import the CA, and chain `Browser → Splice → Burp → target`. |
| [`docs/DESIGN.md`](docs/DESIGN.md) | Architecture, plugin contract, threat model, and Mutant-runtime notes. |

## Chaining with Burp / ZAP / mitmproxy

Splice speaks the standard HTTP proxy protocol, so it chains with other proxies.
Set `"upstream_proxy": "127.0.0.1:8080"` in the config to run
`Browser → Splice → Burp → target`: Splice enforces scope and records the
site-map/findings, then forwards to Burp for interactive work. Out-of-scope hosts
are denied at Splice and never reach Burp. Full walkthrough (CA import, browser
and Burp settings, both topologies) in
[docs/USING_WITH_BROWSER_AND_BURP.md](docs/USING_WITH_BROWSER_AND_BURP.md).

## Running

Splice runs on the Mutant `dev-sec` runtime. Build it once:



`splice.mut` reads its config path from the `CONFIG_PATH` constant at the top of
the file (set it to the absolute path of `splice.config.json`), and the config's
`root` field is the base for all other relative paths. Then compile and run:

```sh
# from the mutant runtime directory:
mutant.exe /path/to/splice.mut --password test          # compiles -> splice.mu
mutant.exe /path/to/splice.mu  --password test --compat
```

Run with **`--compat`** (not `--dev`): the security machinery stays active and the
anti-sandbox check still runs, but on a virtualized/WSL box its `sandbox_detected`
signal is advisory rather than fatal. On a bare-metal deployment box, run with **no
flags** for full terminate-on-tamper enforcement. See [docs/DESIGN.md](docs/DESIGN.md).

After Running splice

Add the ca certificate

```pwsh
certutil -addstore -user Root "splice\ca\splice-ca.pem"
```

### Two modes

Set `mode` in `splice.config.json`.

- **`"mode": "proxy"`** (the shipped engagement default) runs the live
  intercepting proxy — see [docs/USING_WITH_BROWSER_AND_BURP.md](docs/USING_WITH_BROWSER_AND_BURP.md).
- **`"mode": "selftest"`** drives the entire engine against synthetic flows —
  policy, match/replace, graph, secret hunt, all three plugins, and an entry→sink
  attack-path query — with no sockets, and asserts every outcome:

  ```
  === Splice self-test (engine, no sockets) ===
  [1] Policy enforcement (scope / RoE)        PASS x7
  [2] Match / replace on outgoing request     PASS x3
  [3] Graph site-map + finding correlation    PASS x3   (12 nodes, 12 edges)
  [4] Attack-path query (entry -> sink)        PASS
  === Self-test complete: 14 passed, 0 failed ===
  RESULT: OK
  ```

- **`"mode": "proxy"`** runs the live intercepting proxy on `cfg.bind`
  (default `127.0.0.1:8080`). It prints a freshly generated CA certificate —
  trust that CA in your client to intercept HTTPS — then enforces scope on every
  connection. Out-of-scope requests get `403 Forbidden` and never touch the
  upstream:

  ```
  out-of-scope CONNECT  => HTTP/1.1 403 Forbidden
  out-of-scope plain GET => HTTP/1.1 403 Forbidden
  ```

## Status

Both paths are verified end-to-end on the real runtime: the engine self-test
passes 14/14, and the live proxy has been shown to deny out-of-scope CONNECT and
plain-HTTP requests over real TCP without ever contacting the upstream. See
[docs/DESIGN.md](docs/DESIGN.md) for the full architecture and the language
constraints the implementation works within.

> For authorized security testing only. Splice is an interception tool; run it
> exclusively against systems you have written permission to test.
