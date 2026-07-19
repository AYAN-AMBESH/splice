# Splice — Live Demo Plan

A presenter's runbook for demoing **Splice** (the policy-enforced intercepting
proxy built in the Mutant language). Designed for a ~10–12 minute live demo slot.
Everything here has been verified against the real target `whokilledtulpa.com`.

>  *"Your intercepting proxy trusts you to stay in scope.
> Mine doesn't — it enforces it, proves it, and maps everything it sees, in one
> signed binary with no Python or JVM."*

---

## 0. The story arc (what the audience should feel)

1. **The gap** — Burp/ZAP scope is advisory; one fat-finger and you're out of
   bounds. Nobody can *prove* they stayed in scope.
2. **The idea** — scope as *enforced, traced policy*; the site-map as a *real
   graph*; checks as *sandboxed plugins* — all in a self-contained language runtime.
3. **The proof** — live: allow in-scope, **block** out-of-scope before it egresses,
   map the site, find real issues, chain to Burp, all concurrent — then show the
   report.

Keep the emotional beat on the **DENY** (nothing else does this by default) and
the **report** (a deliverable, not a flat issue list).

---

## 1. Pre-demo checklist

- [ ] `mutant.exe` built (`cd mutant && go build -o mutant.exe .`).
- [ ] `splice.mu` compiled fresh:
      `mutant.exe "D:/Security Research/splice/splice.mut" --password test`
- [ ] Splice's CA imported into the demo browser (see walkthrough §3). **Do this
      ahead of time** — never import certs live.
- [ ] `policy/scope.rego` limited to `whokilledtulpa.com` (+ any host you'll show).
- [ ] Decide topology: **standalone** (`upstream_proxy: ""`) is the safest demo —
      no dependency on Burp. Show the Burp chain only if Burp is up and Intercept
      is **OFF**.
- [ ] Delete old logs so the demo starts clean:
      `rm splice-audit.log splice-findings.log`.
- [ ] **Pre-start Splice** and let it finish the ~20 s Argon2 startup *before* the
      slot (start it during the previous slide). Confirm `proxy listening on
      127.0.0.1:8123`.
- [ ] Terminal font large; browser proxy toggle ready (FoxyProxy "splice" profile).
- [ ] A second terminal ready with the curl commands pre-typed (see §3) so you're
      not typing live under pressure.
- [ ] Network: confirm `whokilledtulpa.com` resolves + is reachable on the venue
      network (`curl -sI https://whokilledtulpa.com/`). Have the **offline
      fallback** ready (§5) in case venue wifi dies.

Run command (leave it running in a visible terminal):
```sh
cd "D:/Security Research/mutant"
mutant.exe "D:/Security Research/splice/splice.mu" --password test --compat
```

---

## 2. The four beats (with the point to land)

| Beat | Action | The line |
|------|--------|----------|
| **1. Intercept** | Browse `https://whokilledtulpa.com/` through Splice | "Standard MITM — I see the decrypted traffic." |
| **2. ENFORCE** | Browse `https://example.com/` → **403 block page** | "Out of scope. It didn't just warn me — it *refused* to send it. That 403 is a compliance artifact." |
| **3. MAP + FIND** | Show the console: `[finding] Missing CSP…`, graph growing | "It's building a graph of the site and running sandboxed checks as it goes." |
| **4. REPORT** | Browse `http://splice.report/` | "One URL, and I get the engagement report: what's in scope, every decision, every finding." |

---

## 3. Timed live script (~10 min)

Times are cumulative. Narrate while you do each step.

**[0:00] Frame it (30s).** "This is Splice. It's an intercepting proxy — like
Burp — but written top-to-bottom in a custom language, and it enforces scope
instead of suggesting it. Splice is already running here."

**[0:30] Show it's a real proxy (1 min).** Toggle the browser to the Splice proxy.
Load `https://whokilledtulpa.com/`. Page renders normally. Point at the Splice
terminal: `[allow] CONNECT whokilledtulpa.com (in scope, trace 189 events)` and
`[stream] GET … status=200`.
> "Green padlock — it minted a cert from its own CA. And every allow carries a
> 189-event policy trace: proof, per request, that I was in scope."

**[1:30] THE MONEY SHOT — enforcement (1.5 min).** In the address bar, go to
`https://example.com/`. It returns Splice's **403 block page**:
`Splice: request blocked by engagement policy -- out-of-scope host`.
> "example.com is not in my rules of engagement. Burp would happily send that.
> Splice refuses — the packet never leaves the box. If you've ever sweated 'did I
> accidentally hit prod / a third party', this is the answer."
Then flip to a terminal and `cat splice-audit.log` — show the `DENY` line next to
the `ALLOW`s.
> "And it's all written to an append-only audit trail. That's your proof-of-scope
> for the client report."

**[3:00] The site-map + findings (2 min).** Back in the browser, click around
`whokilledtulpa.com` (homepage → a blog post → an asset). Point at the Splice
console filling with `[finding] medium :: Missing Content-Security-Policy`,
`low :: Missing X-Frame-Options`, `low :: Missing X-Content-Type-Options`.
> "As I browse, it's folding every endpoint, parameter, and finding into a *graph*
> — not a flat tree — and running sandboxed Lua checks on each response. These are
> real: this site ships without a CSP or those headers."

**[5:00] Concurrency (30s, optional).** In the pre-typed terminal, fire the
concurrent batch:
```sh
for n in 1 2 3 4 5; do curl -s -k -x http://127.0.0.1:8123 -o /dev/null "https://whokilledtulpa.com/?b=$n" & done; wait
```
> "Five requests at once, serviced in parallel — each connection gets its own VM."

**[5:30] THE REPORT (1.5 min).** In the browser, go to `http://splice.report/`.
Up comes the plain-text engagement report: scope policy, `Graph sitemap: N nodes,
M edges`, the full audit trail, and the findings list.
> "One URL through the proxy and I get the deliverable: what I was scoped to, every
> allow/deny, and everything it found — no external tooling, no export dance."

**[7:00] Chain to Burp (1.5 min, only if Burp is ready).** Flip `upstream_proxy`
to Burp (or show it pre-configured). Browse again; show the same request now in
Burp's HTTP history *with* the injected `X-Splice-Tester` header.
> "And it composes. Splice sits in front of Burp: it enforces scope and maps the
> site, then hands the in-scope traffic to Burp for Repeater/Intruder. Out-of-scope
> never reaches Burp at all."

**[8:30] Land it (1 min).** "Enforced scope with proof, a queryable site-map
graph, sandboxed checks — shipping as one signed, dependency-free binary you can
drop on a client box. Written in a language whose whole runtime I control." →
transition to your close / repo link.

---

## 4. Optional deep-dive clips

- **WebSocket interception** — full-duplex frame relay + logging (verified live
  against `wss://ws.postman-echo.com`). Show the `[ws c->s]/[ws s->c]` frame log.
- **Attack path** — `db_shortest_path(entry_endpoint, sink_finding)` chains an
  entry point to a sink through the `links_to` (Referer) edges.
- **Add a check live** — drop a 6-line `.lua` into `plugins/`, add it to the
  config, restart: a new detection with no core rebuild. (Rehearse — the restart is
  ~20 s.)
- **The self-test** — `mode: selftest` → `14 passed, 0 failed` proves the engine
  offline in one shot.

---

## 5. Fallbacks & recovery 

- **Venue wifi dies / target unreachable.** Have a **recorded screen capture** of
  the full demo as backup, and/or run Splice against a **local target** you control
  (put `127.0.0.1`/`localhost` in scope + a tiny local server). Rehearse this path.
- **Splice not up / crashed.** It takes ~20 s to start — never restart live if you
  can avoid it. If you must, fill with the architecture slide while it boots.
- **Cert warning in browser.** You forgot the CA import — do NOT fix live; switch
  to the recorded capture or the curl-with-`-k` terminal path:
  `curl -k -x http://127.0.0.1:8123 https://whokilledtulpa.com/`.
- **Burp holds requests / page hangs.** Burp Intercept is ON — say so, turn it off,
  or skip the Burp beat entirely (it's optional).
- **A 304 instead of a body.** The `strip-if-none-match` rule prevents this; if you
  see it, the rule/rebuild didn't take — skip to the report beat.
- **Buffered stdout hides log lines.** The console is block-buffered; if lines
  don't appear, `cat splice-findings.log` / `splice-audit.log` (files flush
  immediately) or hit `http://splice.report/`.

---

## 6. NOT to do live

- Import certificates or change the Windows trust store on stage.
- Point Splice at any host you're not authorized to test — keep scope tight and
  **only** demo against `whokilledtulpa.com` (your own domain) or a local target.
- Recompile the Mutant runtime (`go build`) — do that beforehand.
- Rely on a single network path — always have the recorded fallback.

---

## 7. 20-second elevator version (if the demo slot gets cut)

Load in-scope → 200. Load `example.com` → **403, blocked, never egressed**. Show
`http://splice.report/` → graph size + audit + findings. Done. That's the whole
value in three clicks: *enforced scope, proven, mapped.*
