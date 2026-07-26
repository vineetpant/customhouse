# Bulkhead — Claude Code Instructions

`DESIGN-v2.md` is the source of truth; when it disagrees with this file, it wins.

## Project summary

Bulkhead is a deterministic reference monitor for the MCP tool boundary: an aggregating proxy between an agent client and N upstream MCP servers that enforces the rule that untrusted input can't drive sensitive output. **Hard constraint: no LLM/model call and no network access exists anywhere in the enforcement path — policy evaluation is a pure function.**

## Implementation map (where things are — not a changelog; git has history)

- **Status:** Phase 0 (passthrough proxy) essentially complete: aggregation +
  namespacing + routing, §3 invariant gate, append-only ledger. Next: Phase 1
  (taint/provenance, tiered policy engine, R1–R3, consent) — or §4 metadata pinning.
- **The chokepoint** is `BulkheadProxy::call_tool` in `src/proxy.rs`: every
  `tools/call` runs `invariants.assess()` → `ledger.record_call()` → route. Phase 1
  rules slot in at this exact point. `evaluate()` is the client-clean projection
  of `assess()`; the operator-only matched path stays on `Assessment`.
- **Modules & dependency direction** (leaves at the bottom; no lateral imports):
  `paths` (path resolution + `bulkhead_home()`), `config` (`bulkhead.toml`), and
  `decision` (`Decision`/`Assessment` vocabulary) are leaves; `invariant` (§3 gate)
  and `ledger` (append-only JSONL) depend only on leaves; `upstream` (`Registry`,
  routing, `CallError`) depends on `config`; `proxy` composes everything and owns
  the chokepoint. `invariant`, `ledger`, and `upstream` must not import each other.
  `bin/mock_upstream` and `examples/demo_session` are the network-free fixtures.
- **rmcp 2.2.0 patterns are already verified in-tree** — copy from `proxy.rs` /
  `upstream.rs` rather than re-deriving; read crate source in the registry cache
  before using an unverified API.
- **Live check / demo:** `./demo/run.sh` runs a hermetic end-to-end session
  (`examples/demo_session.rs` is a real MCP client) showing an allow, a deny, and
  the ledger. Use it as the smoke test; it panics if self-protection regresses.

## Architecture rules

- **Aggregating proxy, not a sidecar.** One chokepoint presenting as a single MCP server, multiplexing N upstreams — only it sees cross-server flows (read via web, exfil via mail). Per-server sidecars structurally cannot.
- **§3 self-protection invariants (I1–I5) are compiled into the binary and evaluated before any policy rule** — not expressible or removable in config. Path checks run on the canonicalized path, not the raw argument.
- **The ledger is append-only from the proxy side and unreadable via any mediated path** (reading it re-injects the tainted strings it records).
- **Deterministic rules only. Never pattern-match for "injection-looking" text.** Control is pinning + mutation-blocking + operator visibility, never regex guesswork.
- Consequences to keep consistent: upstream-namespaced tool names (`web__fetch`), merged/rewritten `tools/list`, upstream errors wrapped never swallowed. Errors/prompts never quote tainted content — reference origins by id + domain.

## Workflow rules

- **Propose a plan and get my agreement before implementing.**
- Work in small, individually testable chunks; **commit each working chunk.**
- **Write tests alongside code and run them yourself before telling me a chunk is done.**
- **Never claim something works without running it.**
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
  (`paths`, `config`, `decision`) import nothing from the crate; policy/record
  modules (`invariant`, `ledger`) depend only on leaves; `proxy` is the
  composition root. `invariant`/`ledger`/`upstream` must never import each other
  in production code — if two need a thing, it belongs in a leaf they both depend
  on (that is why `bulkhead_home` lives in `paths` and `Decision` in `decision`).
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
- **Tests are hermetic:** tempdirs, never the real `~/.bulkhead`; a pure unit
  should be testable without spawning a process.
- **New dependency or newtype requires a one-line "considered and rejected"
  rationale** in the commit or code — dep-minimalism is a security property here.

## Commit conventions

- Conventional Commits, imperative mood.
- One logical change per commit.
- Keep the message short: subject line, max ~2 lines total. No long bodies.

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
