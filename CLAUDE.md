# Customhouse — Claude Code Instructions

`DESIGN-v2.md` is the source of truth; when it disagrees with this file, it wins.

## Project summary

Customhouse is a deterministic reference monitor for the MCP tool boundary: an aggregating proxy between an agent client and N upstream MCP servers that enforces the rule that untrusted input can't drive sensitive output. **Hard constraint: no LLM/model call and no network access exists anywhere in the enforcement path — policy evaluation is a pure function.**

## Implementation map (where things are — not a changelog; git has history)

- **Status:** Phase 1 (R3 flow enforcement) is **built and measured**. The
  headline claim is now demonstrable: `./demo/run_flow_block.sh` blocks a
  cross-server exfiltration against the real filesystem MCP server. Measured
  behaviour lives in `METRICS.md` (100% block, 40% false positive).

### Phases (implementation plan)

- **Phase 0 — Reference-monitor foundation. DONE.** Aggregation, namespacing,
  routing; §3 self-protection invariants; append-only ledger; R1 tool-definition
  pinning with `customhouse repin`. Unmediated surfaces (resources, prompts) are
  refused explicitly rather than silently reported empty. Verified against the
  real `@modelcontextprotocol/server-filesystem`, not only the bundled mock.
- **Phase 1 — The moat: deterministic cross-server flow enforcement. DONE.**
  Trust classes per upstream (default untrusted), sink taxonomy, session taint,
  and the flow rule at the chokepoint. `Escalate` plus out-of-band
  `customhouse approve <class>`. Measured: `./demo/run_metrics.sh` → `METRICS.md`.
  Still open from this phase: **value fingerprinting** (evidence quality, not the
  guarantee) and **mid-session pin re-check** on every client `tools/list`.
- **Phase 2 — Numbers.** AgentDojo adapter; paired attack-success and
  task-utility figures published honestly, even if mediocre. This is what turns
  "structural beats signature-based" from an assertion into a result.
- **Phase 3 — Capability profiles (R2)** and footprint/regression diffing.

The thesis is now demonstrated, so the next work is proving it at scale
(Phase 2) rather than broadening surface. Signed receipts, fuzzing, protocol
breadth and extra upstreams remain deferred until the AgentDojo numbers exist.

- **Two enforcement points.** (1) The call chokepoint: `CustomhouseProxy::call_tool`
  runs `invariants.assess()` (§3, compiled-in, always first) → `flow.assess()`
  (R3) → route → taint-if-untrusted. (2) Connect time: `Registry::connect`
  pin-checks each upstream's tools and withholds mutated ones before exposure.
- **The taint guard is held across the whole mediated call**, which serialises
  them. This is load-bearing, not incidental: MCP clients dispatch concurrently,
  and without it a sink can be judged *before* an in-flight untrusted read taints
  the session. Do not "optimise" it away. Residual: arrival order is still
  client-determined — see SECURITY.md.
- **Two decision types, deliberately.** `InvariantOutcome` (Allow/Deny) is what
  §3 returns; `Decision` (Allow/Deny/Escalate) is the flow vocabulary. An
  invariant *cannot* escalate — it is a compile error, not a convention. Widening
  goes one way via `From`. Both stay exhaustive so a new outcome breaks every
  match site instead of falling through a wildcard into "allow".
- **Modules & dependency direction** (leaves at the bottom; no lateral imports):
  `paths` (path resolution + `customhouse_home()`), `config` (`customhouse.toml`), and
  `decision` (outcome vocabulary), `pin` (pin store + canonical diffing),
  `session` (taint state), `sink` (sink taxonomy + matching) and `approval`
  (operator acks) are leaves; `config` depends on `sink`; `invariant` (§3 gate),
  `ledger` and `flow` (the R3 rule) depend only on leaves; `upstream`
  (`Registry`, routing, pinning, trust) depends on `config` + `pin`; `proxy`
  composes everything and owns the chokepoint. `invariant`, `ledger`, `flow` and
  `upstream` must not import each other. Everything under `examples/` is a
  fixture, never product surface: `mock_upstream` and `mock_sink` are stand-in
  MCP servers, the `*_session` files drive the demos. They live in `examples/`
  rather than `src/bin/` precisely so `cargo install` does not put them on a
  user's PATH — do not move them back.
- **rmcp 2.2.0 patterns are already verified in-tree** — copy from `proxy.rs` /
  `upstream.rs` rather than re-deriving; read crate source in the registry cache
  before using an unverified API.
- **Live checks / demos** (each asserts its own property and exits non-zero if it
  regresses — treat them as tests, not narration):
  `./demo/run_flow_block.sh` is **the headline**: cross-server exfiltration
  blocked against the real filesystem MCP server. `./demo/run_selfprotect_real.sh`
  proves self-protection against that same real server. Both need Node, so CI
  runs them non-blocking.
  `./demo/run.sh`, `./demo/run_rugpull.sh` and `./demo/run_metrics.sh` are
  hermetic, need only Rust, and gate CI.
- **Driving demos:** always drive sequentially, awaiting each response, like a
  real agent. Piping several JSON-RPC requests at once races the taint window and
  produces false passes — this bit twice during Phase 1.

## Architecture rules

- **Aggregating proxy, not a sidecar.** One chokepoint presenting as a single MCP server, multiplexing N upstreams, so a cross-server flow (read via web, exfil via mail) is visible in one place. A per-server guard sees only its own half, so the same coverage otherwise requires sharing state between components — aggregation is the option with least coordination, not the only reachable one.
- **§3 self-protection invariants (I1–I5) are compiled into the binary and evaluated before any policy rule** — not expressible or removable in config. Path checks run on the canonicalized path, not the raw argument.
- **The ledger is append-only from the proxy side and unreadable via any mediated path** (reading it re-injects the tainted strings it records).
- **Deterministic rules only. Never pattern-match for "injection-looking" text.** Control is pinning + mutation-blocking + operator visibility, never regex guesswork.
- Consequences to keep consistent: upstream-namespaced tool names (`web__fetch`), merged/rewritten `tools/list`, upstream errors wrapped never swallowed. Errors/prompts never quote tainted content — reference origins by id + domain.

## Workflow rules

- **Propose a plan and get my agreement before implementing.**
- Work in small, individually testable chunks; **commit each working chunk.**
- **Write tests alongside code and run them yourself before telling me a chunk is done.**
- **Never claim something works without running it.**
- **Post-tag, nothing ships without explicit approval.** Once a version is
  tagged and published, the bar changes: propose the change, explain the options
  and trade-offs, and **wait for a decision before writing any code**. Published
  versions are permanent — crates.io can yank but never delete — so a fix that
  seemed obvious in the moment becomes part of the record. This applies to code,
  config, docs and release metadata alike.
- **Reviews are comments, not commits.** A reviewer records findings (e.g. a
  committed `REVIEW.md`) and stops; the implementer applies them and deletes the
  file. The reviewer does not push fixes directly.

## Code conventions

- Rust + tokio.
- **`rmcp` pinned to an exact version. Never generate rmcp API calls from memory — check the pinned version's actual API first.**
- Target MCP spec **2026-07-28** (stateless core) with **2025-11-25** compat.
- License: Apache-2.0.

## Rust design guidelines (hold the line — the codebase is structured this way)

- **Module dependency direction is acyclic and points at leaves.** Leaves
  (`paths`, `decision`, `session`, `sink`, `pin`, `approval`) import nothing from
  the crate; `config` depends only on `sink`; policy/record modules (`invariant`,
  `ledger`, `flow`) depend only on leaves; `proxy` is the composition root.
  `invariant`/`ledger`/`flow`/`upstream` must never import each other in
  production code — if two need a thing, it belongs in a leaf they both depend on
  (that is why `customhouse_home` lives in `paths` and `Decision` in `decision`).
  Exception: `#[cfg(test)]` may cross laterally when the cross-module property
  *is* the test — the I-5 drift test in `ledger` imports `Invariants` by design;
  do not "fix" it.
- **Typed errors per module; no `Box<dyn Error>` in library code.** Each module
  owns a `thiserror` enum whose variants name the actual failure (build-time vs
  call-time are different types — `UpstreamError` vs `CallError`). Preserve
  `#[source]` chains; don't downgrade a typed source to `String`. `Box<dyn Error>`
  is allowed only in `main`/examples, never in exported `lib` signatures.
- **No stringly-typed domain values.** Use enums with serde renames (e.g. the
  ledger `decision`), not `&'static str`.
- **Never re-derive structured information from strings.** If the system already
  holds a fact structurally (the `Registry` knows a tool's server), pass it —
  don't re-parse `web__fetch`.
- **Pure core, impure shell.** Keep decision logic a pure function of its inputs
  (fs reads for canonicalization are allowed — see Corrections). Side effects
  (ledger writes, stderr, process spawning) live at the edges.
- **Return typed results, not `Option<Result<..>>`** or other nested-maybe shapes
  that push branching onto callers.
- **Client-facing vs operator-facing types stay separate by construction.**
  `Decision` (crosses to the client) carries no path; `Assessment` (operator-only)
  does. Don't merge them.
- **Tests are hermetic:** tempdirs, never the real `~/.customhouse`; a pure unit
  should be testable without spawning a process.
- **New dependency or newtype requires a one-line "considered and rejected"
  rationale** in the commit or code — dep-minimalism is a security property here.

## Writing and positioning rules

These govern README, SECURITY.md, DESIGN, release notes and any public copy.

- **Never write our own product down.** Do not rank it below alternatives, do not
  route readers elsewhere, do not hedge the claim into meaninglessness. Honesty
  about *our own limits* (SECURITY.md, the measured false-positive rate) is a
  different thing and stays blunt — that is a spec, not an apology.
- **Never write another product down either.** No disparagement, no implied
  deficiency, no "unlike X which fails to…". Name neighbours factually or not at
  all. We do not know their codebases, their roadmaps, or their reasons.
- **No claim of uniqueness or superiority without evidence in hand.** "First",
  "only", "nobody else", "structurally cannot" require something verifiable —
  a quote from their docs, a measurement, a reproducible test. If it cannot be
  cited, it does not go in. Inferring capability from a CLI example is not
  evidence; that mistake produced a false "single-server proxies structurally
  cannot do this" claim that their own docs disprove.
- **Prefer claims about what we did over claims about what others didn't.** "We
  publish a block rate and a false-positive rate" is verifiable and needs no
  comparison. "We are the only ones who do" needs proof we cannot fully have.
- **Assume the category is real and contested, not empty.** Market validation
  comes from users, not from our own assessment of our design. Until there is
  adoption evidence, describe the product, not its standing.

## Commit conventions

- Conventional Commits, imperative mood.
- One logical change per commit.
- Keep the message short: subject line, max ~2 lines total. No long bodies.
- No `§`/design-section references in commit messages — a git log reader may not
  have `DESIGN-v2.md` open. Keep `§` refs in code comments, where the doc is right
  there; commit subjects describe the change in plain terms.

## Things to never do

- No LLM in the enforcement path.
- No network in the enforcement path.
- Don't invent MCP methods or rmcp APIs.
- Don't widen scope beyond the current phase.
- Don't mark a task done without a passing test.

## Corrections

<!-- New rules get appended here as we discover them during implementation. -->

- **Protocol/SDK reality (2026-07-25):** latest stable `rmcp` is `2.2.0`, which
  implements **MCP 2025-11-25**, not 2026-07-28. Phase 0 pins `rmcp =2.2.0` and
  targets 2025-11-25. The design's "2026-07-28 primary" is a migration target to
  adopt when `rmcp` ships it stable (currently only in the `3.0.0-beta` line).
- **"Pure function" includes local filesystem reads:** the §3 invariant gate
  canonicalizes paths (resolving symlinks, `..`, `~`), which reads local FS
  state. This is deterministic, local, and *required* by §3's symlink-resolution
  mandate — the decision is a pure function of (arguments, filesystem state) with
  no network or model dependency. "Pure" means no LLM/remote/nondeterminism, not
  "cannot touch the filesystem."
