# Review — post-refactor (Fable, 2026-07-26)

Reviewer: Fable. Implementer: Opus — address each item, check it off, delete this
file in the final commit. Verdict on the refactor itself: **up to mark, approved.**
The six chunks match the plan; the `decision` leaf extraction and the two
deviations (`server` on `Route`, boxed `ServeError::Server` source) were correct.
Items below are what a fresh pass over the result surfaced.

## Blocking before any public push

- [ ] **`Cargo.toml:8`** — `repository = "https://github.com/REPLACE_ME/bulkhead"`.
  Placeholder. Ask the user for the real URL (or drop the field until the repo
  exists); do not guess.

## Minor (code/manifest)

- [ ] **`Cargo.toml:27`** — tokio feature `signal` is unused (`grep tokio::signal src/`
  is empty). Remove it; dep-minimalism is one of our own guidelines.
- [ ] **`src/invariant.rs:27`** — module doc says "`Decision` here is Allow/Deny
  only"; `Decision` no longer lives *here* (moved to `decision`). Reword to point
  at `crate::decision::Decision`.
- [ ] **`src/decision.rs`** — add a doc line on `Decision`: it is deliberately
  exhaustive (no `#[non_exhaustive]`), so that when Phase 1 adds `Escalate` the
  compiler forces every match site to handle it instead of a wildcard arm
  silently allowing. Without the comment, someone will "future-proof" it.
- [ ] **`src/ledger.rs`** module doc — state that the JSONL entry schema is a
  contract for offline consumers (Phase 3 footprint diffing reads these files):
  evolve additively, new optional fields only, never rename/repurpose.

## Minor (CLAUDE.md — guidelines drift)

- [ ] **Guidelines leaf list disagrees with the map in the same file.** The map
  names three leaves (`paths`, `config`, `decision`); the guidelines bullet says
  "Leaves (`paths`, `config`)". Fix the bullet to include `decision`.
- [ ] **Add the `#[cfg(test)]` carve-out** to the no-lateral-imports rule: the
  I-5 drift test in `ledger` imports `Invariants` *by design* (it is the test
  that catches gate/ledger home drift). State the exception explicitly or a
  future session will "fix" that test and delete the load-bearing check.

## Process note

- [ ] Add one line to CLAUDE.md Workflow rules: review findings arrive as
  comments (this file's pattern); the implementer applies them — the reviewer
  does not push fixes directly.

## Explicitly fine (reviewed, no action)

- `ServeError::Server` boxed source: rmcp's `mod server` is private, the error
  type is unnameable — boxing is forced, not lazy. Keep the explanatory comment
  when touching it.
- `main.rs` stringly errors: `main` is the impure shell; acceptable.
- No further module restructuring for Phase 1/3 — the current shape absorbs
  `pin`, `provenance`, `policy`, `session`, `consent` as new modules without
  moving anything. Expect (don't pre-build) a `proxy/` directory split when §5
  mediation scope lands.
