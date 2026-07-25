# Bulkhead — Claude Code Instructions

`DESIGN-v2.md` is the source of truth; when it disagrees with this file, it wins.

## Project summary

Bulkhead is a deterministic reference monitor for the MCP tool boundary: an aggregating proxy between an agent client and N upstream MCP servers that enforces the rule that untrusted input can't drive sensitive output. **Hard constraint: no LLM/model call and no network access exists anywhere in the enforcement path — policy evaluation is a pure function.**

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

## Code conventions

- Rust + tokio.
- **`rmcp` pinned to an exact version. Never generate rmcp API calls from memory — check the pinned version's actual API first.**
- Target MCP spec **2026-07-28** (stateless core) with **2025-11-25** compat.
- License: Apache-2.0.

## Commit conventions

- Conventional Commits, imperative mood.
- One logical change per commit.

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
