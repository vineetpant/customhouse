# Bulkhead — Design Document v2

> Deterministic enforcement at the MCP tool boundary.
> Working name changed from "Airlock" (v1): Airlock Digital is an established
> application-allowlisting vendor in the same security space. "Bulkhead" — the
> ship wall that contains flooding to one compartment — is the correct metaphor
> for blast-radius containment. **Verify crates.io / npm / GitHub availability
> before the repo goes public; rename is a one-line find/replace today and a
> broken-links problem later.**

**One-line thesis:** the model cannot be trusted to decide what actions are safe, so the decision moves outside the model into a deterministic reference monitor that sits between the agent and every tool it can reach.

**Hard constraint:** no LLM call, no model judgment, and no network access exists anywhere in the enforcement path. Policy evaluation is a pure function. Broken once, the project has reintroduced the vulnerability it claims to fix.

---

## 0. Changes from v1 (review findings → sections)

| # | Finding | Addressed in |
| --- | --- | --- |
| 1 | Proxy disarmable through its own proxied surface | §3 Self-protection invariants |
| 2 | Tool metadata is an unlabeled injection channel; rug pulls | §4 Metadata pipeline; R1 revised |
| 3 | "Session" undefined; 2026 spec removed protocol sessions | §6 Session & taint lifecycle |
| 4 | Mediation only covered `tools/call` | §5 Mediation scope |
| 5 | Publisher-signed manifests have no ecosystem yet | §9 Local-first profiles |
| 6 | Escalation races client timeouts | §10 Consent under time pressure |
| 7 | Chunked exfil; entropy false-positives on own secrets | §7.4, §7.5 |
| 8 | Name collision | Header note above |
| — | Week numbers were optimistic | §11 Phases are a sequence, not a schedule |

---

## 1. Threat model

**In scope**

| Threat | Example |
| --- | --- |
| Indirect prompt injection | Tainted web/email/file content drives an unintended tool call |
| Exfiltration via permitted tools | Source and sink individually allowed; the *flow* is the attack |
| **Tool poisoning / rug pulls** | Injection payload in tool descriptions; definitions mutate mid-session |
| **Self-disarm** | Agent is steered into editing Bulkhead's own policy/ledger through a proxied filesystem tool |
| Over-permissioned skills | A skill reaches tools and scopes it never needed |
| Supply-chain substitution | Artifact is not what the publisher (or the user, at pin time) attested |
| Silent permission drift | A new version quietly widens its effective footprint |
| **Chunked / low-and-slow exfil** | Secret split into sub-threshold fragments across many calls |

**Out of scope (v1 — say so in the README)**

- Malicious *client* or compromised host OS: Bulkhead trusts the process boundary it runs in. It is a reference monitor, not a sandbox; pair with OS-level sandboxing for hostile-host threat models.
- Attacks that live entirely in model output text and never reach a mediated call.
- Semantic laundering of tainted content (§7.3 — mitigated by sink tiering, not solved).
- Multi-tenant / enterprise policy distribution.

**Security properties targeted** (Anderson's reference-monitor criteria, used as the review checklist):

1. **Complete mediation** — no content-bearing MCP interaction reaches model context or an upstream server without classification (§5 defines exactly which methods, and what v1 refuses to proxy at all).
2. **Tamper resistance** — enforced by hard invariants (§3), not by policy.
3. **Verifiability** — the policy engine is small, pure, exhaustively unit- and property-testable.

---

## 2. Topology

```
      Agent client  (Claude Code / OpenClaw / custom)
            │  stdio  or  Streamable HTTP
            ▼
    ┌───────────────────────────────────────┐
    │              BULKHEAD                 │
    │ shim → metadata pin → labels →        │
    │ provenance → policy → consent → ledger│
    └───────────────────────────────────────┘
        │           │            │
        ▼           ▼            ▼
     web-fetch   filesystem    mail / github / …
     (upstream MCP servers)
```

**Bulkhead is an aggregating proxy** — it presents as a single MCP server and multiplexes N upstreams. The attack is a *cross-server* flow (read via web server, exfiltrate via mail server); a per-server sidecar structurally cannot see it. Only a single chokepoint satisfies complete mediation.

Consequences: upstream-namespaced tool names (`web__fetch`, `mail__send`), merged/rewritten/cached `tools/list`, wrapped (never swallowed) upstream errors.

**Protocol target:** MCP **2026-07-28** primary (stateless core, no initialize handshake, version/capabilities in `_meta` per request), **2025-11-25** compatibility path for the deployed base. Note: statelessness simplifies proxy plumbing but deletes the protocol-level session the taint model would have leaned on — Bulkhead therefore defines its own session concept (§6).

**Language:** Rust (`rmcp`, tokio). Single static binary, one-line drop-in to an existing client config. Distribution friction is a security-adoption factor. Pin the `rmcp` version explicitly; the SDK has moved fast and code generated from memory of older APIs will be stale.

---

## 3. Self-protection invariants (new — finding #1)

The v1 design was disarmable: a proxied filesystem server could be steered into rewriting Bulkhead's own policy file, after which the *next* call is legitimately allowed. Therefore:

**Invariant set, compiled into the binary, evaluated before any policy rule, not expressible or removable in any config:**

- I1. Any mediated operation whose target resolves inside the Bulkhead home directory (config, policy, ledger, fingerprint store, consent socket) → **Deny**. Path resolution happens after canonicalization (symlinks, `..`, homedir expansion) — the check runs on the resolved path, not the argument string.
- I2. Any mediated operation targeting the Bulkhead binary itself or its containing directory → **Deny**.
- I3. Any mediated exec/shell argument that references the Bulkhead home directory or binary path (post-normalization, §7.4 pipeline) → **Escalate** minimum, regardless of tier.
- I4. Policy and config files are loaded at startup and on explicit operator reload (signal / CLI), never re-read mid-flight because a file changed. A policy change therefore requires an action outside the mediated surface.
- I5. The ledger is append-only from the proxy's side; no mediated path can read it (the ledger records flows — letting the model read it re-injects every tainted string it mentions).

Limitations stated honestly: I1–I3 protect against the *mediated* surface only. An agent with unmediated shell access outside MCP defeats this — that is the out-of-scope malicious-host case, and the README says so. Defense in depth: recommend running Bulkhead state under a different OS user than upstream filesystem servers.

---

## 4. Metadata pipeline (new — finding #2)

Tool descriptions and schemas are attacker-controlled text that lands directly in model context. v2 treats server metadata as a first-class untrusted input:

- **Pin at first sight.** On first `tools/list` from an upstream, Bulkhead canonicalizes and hashes each tool definition (name, description, input schema) and writes the pin set to its own store (protected by §3). Same for `resources/list` and `prompts/list` metadata.
- **Rug-pull detection.** Every subsequent list is re-hashed and diffed against pins. A changed definition → withhold the changed tool (serve the pinned version is *wrong* — the server would still execute the new behavior; withholding is the only honest option), surface a diff to the operator, require explicit re-pin to restore. Ledger-record every mutation event.
- **Descriptions are labeled.** Metadata carries `trust: untrusted` in the ledger like any content. v1 does **not** attempt pattern-based sanitization of descriptions — pattern-matching "injection-looking text" is model-adjacent guesswork and violates the determinism constraint in spirit. Pinning + mutation-blocking + operator visibility is the deterministic control; the pin-review step (operator sees each description once, at pin time) is where a human reads what the model will be reading.
- **Version binding.** A pin set is bound to the upstream's declared implementation name/version; a version change invalidates pins and triggers the same re-pin flow — which is also the hook where §9 profile diffing lands ("v1.4.3 requests capabilities v1.4.2 did not").

This replaces the v1 framing of R1. Signature verification (when a publisher provides one) is now *one input* to pinning, not the whole mechanism.

---

## 5. Mediation scope (new — finding #4)

Complete mediation is claimed only over what is actually mediated, so v1 is explicit about the full MCP method surface:

| Method / feature | v1 treatment |
| --- | --- |
| `tools/call` | Fully mediated: policy + provenance + labeling |
| `tools/list` | Pinned & diffed (§4) |
| `resources/read` | **Fully mediated ingress**: results labeled/fingerprinted exactly like tool results |
| `resources/list`, `prompts/list` | Pinned & diffed |
| `prompts/get` | Mediated ingress (server-authored text entering context → labeled) |
| Sampling (server→client completion requests) | **Deny by default** (config to allow with escalation). Deprecated by SEP-2577 but still functional; a server driving the client's model is an injection superhighway |
| Elicitation | Passed through, ledger-logged; content labeled untrusted |
| Tasks extension | Not proxied in v1 — **refused with a clear error**, on the roadmap (needed for §10 long waits) |
| MCP Apps (server-rendered UI) | Not proxied in v1 — refused with a clear error. A whole rendering surface is out of v1 scope, and pretending otherwise would be false mediation |
| Notifications | Forwarded, ledger-logged |

The README's claim becomes: *complete mediation over tools, resources, and prompts; sampling denied; Tasks and Apps explicitly unsupported in v1.* Narrower and true beats broad and false.

---

## 6. Session & taint lifecycle (new — finding #3)

The 2026-07-28 spec removes protocol sessions, and MCP has never signaled conversation boundaries. Bulkhead defines its own session, and the doc states the failure mode being managed: **label creep** — without resets, every long-lived deployment converges to permanently-tainted and escalation fatigue kills the tool.

- **Scope.** stdio: one session per client connection (process lifetime). Streamable HTTP: sessions keyed on client identity (auth principal where present, else per-connection), never global.
- **Reset, three paths:**
  1. Connection end.
  2. Idle timeout (default 30 min without a mediated call) — taint state and per-session fingerprint store cleared, reset ledger-recorded.
  3. Explicit operator reset: a Bulkhead-owned `bulkhead__reset_taint` tool exposed to the client — **gated by consent (§10)**, because a model that can silently reset its own taint has no taint. The consent prompt shows what is being forgotten ("clears taint from web:evil.test, mail:inbox — 3 origins").
- **No decay.** Taint does not fade with time within a session; partial-decay schemes are unprincipled knobs. It is binary per origin per session, cleared only by the three paths above.
- **Cross-session persistence (the file-laundering hole).** An agent that writes tainted content to a file and reads it back next session has laundered the label. v1 answer, kept deliberately narrow: when a mediated *write* carries tainted-derived content, the ledger records `(resolved path → origins)`; a later mediated *read* of that path (any session) re-attaches those origins. This covers the proxy-visible laundering path. Out-of-band writes are the malicious-host case. A full persistent-label store is future work; the doc says which half is covered.

---

## 7. The taint model

### 7.1 Sources

Default-deny attribution: content is **untrusted** unless positively attributable to a trusted origin.

| Trusted | Untrusted |
| --- | --- |
| User's typed input | Web fetches |
| System prompt / agent config | Email, chat, issue bodies |
| Explicitly allowlisted internal services | Files in shared or user-writable paths |
| | Any third-party MCP server result |
| | **Server metadata: descriptions, schemas, prompts** |
| | Subagent output derived from any of the above |

Classification: config table keyed on `(server, tool)` with optional per-argument refinement, plus §6 path-origin re-attachment.

### 7.2 Labels

```
Label { trust: Trusted | Untrusted, origins: Set<OriginId>, first_seen: ts }
```

Two-point lattice, deliberately. Every added level multiplies rule surface and false-positive surface.

### 7.3 Propagation — the central design compromise

A boundary proxy cannot see inside the model; once untrusted content enters context there is no token-level visibility into influence. Two mechanisms, both shipped, applied by sink tier (§8):

**Session taint (conservative, high tier).** Untrusted content entered this session ⇒ high-tier sinks escalate. Sound, blunt, unusable as a universal rule.

**Provenance matching (default, medium tier).** Ask "do these outbound arguments *derive* from untrusted content?": normalize (NFKC, case fold, whitespace collapse, homoglyph map) → decode (base64/hex/percent/quoted-printable, recursive, depth-capped, each layer re-enters the pipeline) → shingle (Rabin–Karp k-grams, k≈8, winnowed index) → coverage score → entropy check on unexplained opaque blobs.

**Honest limitation, in the README, not discovered by a reviewer:** provenance matching catches verbatim and near-verbatim flows; it cannot catch *semantic laundering* (model re-expresses tainted content in its own words — an implicit flow invisible at any boundary). The mitigation is exactly the tiering: where laundering is catastrophic (money, keys, exec, new recipients), session taint governs, not string matching.

### 7.4 Evasion resistance (new — finding #7)

- **Chunked exfil.** Per-call coverage scoring misses secrets split into sub-k fragments across calls. Bulkhead keeps a per-`(origin, sink-destination)` **cumulative coverage score across the session**; crossing the aggregate threshold escalates even though no single call fired. Deterministic, session-scoped, cleared on reset.
- **Resource-exhaustion via decode.** Depth cap, size cap, and a per-call time budget on the §7.3 pipeline. Budget exceeded ⇒ **Escalate** (fail closed but visible), never silent allow, never silent drop.
- **Fragmenting below k.** Noted openly as residual risk: k-gram matching has a floor. The cumulative score narrows it; sink-side argument-shape constraints (R2) narrow it further; it does not vanish. Stated, not hidden.

### 7.5 Entropy false-positives (new — finding #7b)

The user's own legitimate API keys in tool arguments are high-entropy and would trip the opaque-blob check daily, after which the check gets disabled and protects no one. v1: a **known-secrets register** — the operator registers secret *digests* (never values) at setup; outbound blobs matching a registered digest at a declared placement (e.g. this server's auth argument) are exempt from the entropy flag while still ledger-recorded. Unregistered high-entropy blobs still flag.

### 7.6 Error hygiene

Denials and escalation prompts must never quote tainted content verbatim — an error message echoed into model context is re-injection through the proxy's own mouth. `FlowSummary` references origins by id and domain ("content derived from web:evil.test, fetched 40s ago"), never by excerpt.

---

## 8. Sinks and decisions

| Tier | Examples | Default treatment |
| --- | --- | --- |
| **High** | Payments, key signing, shell exec, sending to a recipient not previously seen in this session's trusted inputs | Session taint: escalate if any untrusted content entered the session |
| **Medium** | Outbound HTTP with body/query, email/chat send, file write outside scratch | Provenance: escalate/deny only on derived arguments (incl. §7.4 cumulative) |
| **Low** | Read-only, idempotent, local | Allow; log |

Three tiers, not twenty. "New recipient" is defined narrowly and deterministically: an address/handle argument value not present in this session's trusted inputs or the operator's static contacts allowlist — no address book intelligence in v1.

Decisions: `Allow` · `Escalate` · `Deny`. Three, not two — hard-deny everything and the tool is uninstalled in a week, which protects nobody. Every approval writes a **declassification record** (who approved, which flow, which origins released) — the formal answer to "what is your declassification policy."

---

## 9. Capability profiles — local-first (rewritten — finding #5)

v1 assumed publisher-signed manifests; no such ecosystem exists, and shipped that way R1/R2 are dead on arrival. Reordered:

- **v1: operator-authored profiles.** You write a TOML profile per upstream server — AppArmor-style — declaring tools, network domain allowlist, filesystem read/write prefixes, exec permission, and default emitted trust. Bulkhead can bootstrap a draft profile from observed Phase-0 ledger data (the `audit2allow` arc: observe → generate → tighten → enforce).
- **v1.x: community profile repo.** Reviewed profiles for popular servers; profile quality becomes a shared good and the project's first network effect.
- **Later: publisher signatures** (ed25519/minisign first, sigstore-style transparency after) as an additional trust input to §4 pinning — the ecosystem play, not the v1 dependency.

Profile sketch:

```toml
[server]
name = "web-fetch"
pinned_version = "1.4.2"          # binds §4 pin set

[capabilities]
tools = ["fetch", "search"]
network.allow = ["*.wikipedia.org", "api.example.com"]
filesystem.read = []
filesystem.write = []
exec = false

[data]
emits_trust = "untrusted"
```

---

## 10. Consent under time pressure (new — finding #6)

A blocked call waiting on human approval races the client's tool timeout (commonly ~60s); losing that race silently is a broken UX that trains users to pre-approve everything.

- **Approval budget** default 45s, configurable; expiry ⇒ **Deny** with an error explicitly saying approval timed out (distinguishable from a policy deny, so the operator can retry after approving).
- **Fast paths:** controlling-TTY prompt; localhost approval endpoint + optional desktop notification for headless runs.
- **Scoped memory:** an approval can mint a narrow allow rule ("this flow: origin web:docs.rs → sink mail__send, this session") so repeated identical flows don't re-prompt — habituation is managed by making repeat approvals unnecessary, not by making them easy.
- **v1.1:** the Tasks extension is the structural fix for long waits (call parked as a task, polled after approval); adopting it is tied to lifting the §5 Tasks refusal.

---

## 11. Rules, phases, benchmarks

**The v1 rules — exactly three, each mapped to a named 2026 incident class:**

- **R1 — Integrity & pinning** (§4): artifact hash/signature when available; tool-definition pinning and rug-pull blocking always. *Maps to:* LiteLLM PyPI supply-chain backdoor; MCP tool-poisoning class.
- **R2 — Capability profile, checked on argument shape** (§9): by effect and argument shape, never by tool name alone — domain allowlists, path prefixes post-canonicalization, exec constraints. *Maps to:* the Cursor allowlist bypass (allowlisted *name*, hostile payload).
- **R3 — Taint → sink** (§7–8): untrusted-derived data must not reach an exfiltration sink; provenance for medium tier, session taint for high tier, cumulative scoring against chunking. *Maps to:* EchoLeak-class zero-click exfiltration. The rule that justifies the architecture and demos best.

**Phases — a sequence, not a schedule** (v1's week numbers were optimistic; order is the commitment):

- **Phase 0 — passthrough proxy.** Aggregating shim, namespacing, §4 pinning, full ledger, policy hardwired to Allow. Shippable alone as an observability tool, and it generates §9 draft profiles. Includes §3 invariants from the first commit — self-protection is not a later feature.
- **Phase 1 — labels and policy.** Taint, provenance, pure policy engine, R1–R3, consent channel with budget.
- **Phase 2 — demo and numbers.** Qualitative: two identical agents, identical permissions, one behind Bulkhead; a real indirect-injection payload; one exfiltrates, one is blocked with the flow explained. Quantitative: AgentDojo, publishing **paired** attack-success and task-utility numbers, honestly even if mediocre — a measured mediocre result is credible, an unmeasured strong claim is not. *Named workstream:* the AgentDojo adapter — its harness drives Python function tools, so benchmarking means wrapping its suite as MCP servers behind the proxy. Real engineering, budgeted as such.
- **Phase 3 — profiles and regression diffing.** Footprint capture as union-with-frequencies over N runs (agents are non-deterministic; naive diffs are flaky noise), declared-vs-observed diffing, CI reporter. Cheap by then — the ledger has held the data since Phase 0.

---

## 12. Non-goals (README material)

- Not a model-based guardrail or classifier; no pattern-matching for "injection-looking" text anywhere.
- Not a sandbox: pairs with OS sandboxing, does not replace it (§3 limitations).
- Not a general-purpose firewall; not enforcement inside the model.
- Not a framework: MCP only, deeply.
- Not multi-tenant policy distribution in v1; Tasks and MCP Apps explicitly unsupported in v1 (§5).

---

## 13. Decisions taken

| Decision | Choice | Why |
| --- | --- | --- |
| Proxy shape | Aggregating chokepoint | Only position that sees cross-server flows |
| Self-protection | Compiled-in invariants, pre-policy | Tamper resistance can't live in the thing being tampered with |
| Metadata | Pin + diff + withhold on mutation | Deterministic answer to tool poisoning; no sanitization guesswork |
| Session | Proxy-defined: connection / idle-timeout / consent-gated reset | 2026 spec deleted protocol sessions; label creep must be managed explicitly |
| Mediation claim | Tools + resources + prompts; sampling denied; Tasks/Apps refused | Narrow and true beats broad and false |
| Profiles | Local-first, community repo, signatures later | No signing ecosystem exists; dead rules help nobody |
| Language / protocol | Rust + `rmcp` (pinned); 2026-07-28 primary, 2025-11-25 compat | Single binary; stateless core simplifies proxy |
| Policy language | TOML/YAML v1; Cedar noted for later | Rule vocabulary must stabilize before a policy DSL |
| Lattice / tiers | Two-point; three tiers | False-positive surface control |
| Escalation timeout | Deny, distinguishable from policy deny | Fail closed without gaslighting the operator |
| Ledger default | Shapes + digests, values only under flag; unreadable via mediated paths | The ledger must not become the exfil target or a re-injection channel |
| License | Apache-2.0 | Patent grant matters for security infra |

---

## 14. Success criteria for v1

1. A real indirect-injection attack blocked, flow explained in one human-readable sentence.
2. A tool-definition rug-pull blocked and surfaced (the §4 demo — cheap to build, very persuasive).
3. Published AgentDojo numbers: attack-success and utility, side by side.
4. One-line install into an existing MCP client config.
5. False-positive rate low enough that the author leaves it enabled on his own daily setup — the only benchmark that predicts anyone else will.
