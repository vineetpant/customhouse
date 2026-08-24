# Review — open items after v0.3.1 (commit 3971ae0, untagged)

Reviewer: comments only, no code changes. Delete this file once the items are
resolved or moved somewhere durable.

**Not for committing.** By decision, review files stay out of version control.
That makes this file the only carrier of the open backlog, so Part 3 restates
every unresolved item in full rather than pointing at earlier reviews — their
contents are not recoverable from git.

Verification basis: `cargo test --all-targets` → 124 passed. `demo/run.sh`,
`demo/run_rugpull.sh` green. `demo/run_metrics.sh` regenerated `METRICS.md` with
no diff. Every finding below was reproduced as an executable probe against the
current tree, not inferred from reading. Probe files deleted; working tree clean.

Nothing here blocks tagging 0.3.1.

---

## Part 1 — the measurement result worth acting on

The recipient rule has been tightened three times: bracketed strings (a0e0a86),
then structural values and bare lists (3971ae0). Each tightening was argued as
paying a false-positive cost to close a gap. The measured rate has not moved
once — still **100% block (12/12), 30% false positive (3/10)**.

That is the strongest evidence in the repository that the exemption was
*over-broad rather than finely tuned*. Three independent narrowings, zero
measured cost. It is currently invisible: it exists only as a number that
stayed the same across three commits, which reads as "nothing happened."

This is a publishing input, not a code change — see Part 4.

---

## Part 2 — new findings

Both follow from the N2 fix moving recipient-declaredness into the type system.
Neither is a security issue; both are places where the code no longer says what
it means.

### F1. LOW — `classify`'s `recipients_declared` parameter is vestigial

**Where:** `src/destination.rs` `classify`, parameter `recipients_declared: bool`;
sole production caller `src/flow.rs`.

Since `CallRecipients` became a three-state enum, `flow.rs` passes a literal
`true`, because `CallRecipients::Undeclared` is filtered out by the pattern match
and can no longer reach `classify`. The parameter has exactly one production
value, and `NoExemptionReason::RecipientsUndeclared` is unreachable outside
tests.

This is redundant state duplicating what the enum already encodes — the shape
CLAUDE.md's Rust guidelines exist to prevent. Harmless today; the risk is drift.
A future caller passing `false` would take a path production never exercises and
no measurement covers.

**Fix:** drop the parameter and let the type carry the fact. If the variant is
worth keeping for the ledger (F2), it should be produced by the caller that
knows recipients were undeclared, not by a bool passed into a function that can
no longer receive one. Mechanical; existing tests cover the behaviour.

### F2. LOW-MEDIUM — every `NoExemptionReason` is computed, and none reaches an operator

**Where:** `src/destination.rs` `reason_str`; `src/ledger.rs` `record_flow`.

`reason_str()` has no production caller — every use in the tree is a test
assertion. `record_flow` writes `outcome`, `tainted_by`, `matched_author` and
`agreeing_sources`, never the reason. Six reason codes, newly extended with
`recipient_unparseable`, visible to nobody.

The doc comment on `NoExemptionReason` says it "Carries why, for the operator
record." That is currently untrue.

**Why this matters more after 3971ae0 than before it.** The release added
refusal paths whose operator meaning is entirely different from the existing
ones:

- `foreign_recipient` — the rule worked. Someone tried to send to a third party
  in a tainted session and was stopped. Nothing to do.
- `recipient_unparseable`, or an `Opaque` recipient set — **Customhouse could not
  read the call.** The block may be correct, or the operator's mail server may
  use an address form the deliberately-narrow parser refuses, or their sink may
  pass recipients in a shape the collector calls opaque.

From the ledger those are the same line today. For a project that publishes a
false-positive rate and asks operators to tune `require_approval` per class, the
difference between "blocked correctly" and "blocked because we could not read
your data" is the most actionable thing a flow entry could carry. It is also the
feedback loop that would reveal whether the narrow parser is too narrow in the
field — currently unobservable, including to you.

**Fix:** carry the `NoExemptionReason` (or the whole `DestinationVerdict`) on
`FlowAssessment` and emit it as an optional `exemption_declined` field on the
flow entry. The ledger schema is documented as additively evolvable, so a new
optional field is in-contract. Scope it to `external_send` entries where the
class was eligible — a reason on a call that was never an exemption candidate is
noise.

This is the one item here with user-visible value. F1 is tidying.

---

## Part 3 — open backlog, restated in full

These have survived three review cycles. Restated because no earlier file exists
to point at.

### Architectural drift — one commit, no behaviour change

- **`ledger` imports `flow` in production code.** `src/ledger.rs:32` —
  `use crate::flow::FlowAssessment;`. CLAUDE.md forbids
  `invariant`/`ledger`/`flow`/`upstream` importing each other; shared types move
  to a leaf. Fix: move `FlowAssessment` and `Exemption` (consider
  `CallRecipients`) into `decision`, which already holds the operator-side
  `Assessment` and is the outcome-vocabulary leaf both depend on.
- **CLAUDE.md's module map has drifted.** It omits `destination` and `init`
  entirely, and asserts the non-import rule that `ledger.rs:32` breaks. Drifted
  further in 3971ae0: `CallRecipients` became three-state policy vocabulary
  living in `flow`, which is the kind of type the map says belongs in a leaf.
  Fix in the same commit as the item above so rule and tree agree again.

### Correctness and hardening — proposed for 0.4.0

- **`init` silently drops `env`, and there is no operator workaround.**
  `UpstreamConfig` has no `env` field, and `#[serde(deny_unknown_fields)]` means
  a hand-added one is a hard parse error. Any upstream needing an API key is
  unusable behind Customhouse except via a wrapper script. Claude Desktop entries
  routinely carry `env`. Fix: add `env: HashMap<String, String>` to
  `UpstreamConfig`, pass through to the child-process spawn, and have `init`
  carry values across. Touches the serve path.
- **Upstreams inherit Customhouse's cwd.** `Upstream::connect` never calls
  `.current_dir()`. SECURITY.md documents that a bare filename with no separator
  is not treated as path-like; cwd inheritance is what makes that reachable — run
  the proxy from inside `~/.customhouse` and `{"path": "ledger.jsonl"}` resolves
  onto the protected ledger undenied. Verified. Fix: set an explicit
  `current_dir` for spawned upstreams, or document the amplifier.
- **Approval single-use is not durable against a write failure.** In
  `proxy.rs`'s `Escalate` arm, `consume()` removes the grant in memory, `save()`
  failure only prints to stderr, and the store is re-opened from disk on every
  escalation. A persistent write failure leaves the grant on disk and
  re-spendable — "single use" degrades silently to a standing approval. The one
  place in the flow path that fails open.
- **`verify` stops at the first unreadable line**, so entries past it are never
  checked — a single corrupted line ends verification there and later tampering
  behind it goes unreported. Now disclosed in SECURITY.md; the fix (report every
  break and continue) is not implemented.
- **`verify` and `resume_from` both read the whole file into memory.** Slightly
  more relevant since 3971ae0, which added a fragment scan per unparseable line.
  No urgency; switch to a `BufReader` line stream when the file is next touched.

---

## Part 4 — publishing

### `docs/destination-classification.md` is unpublished, and its framing is now stale

Verified: front matter says `published: false`, and `docs/index.md` links only
the false-positives post. The post is written as a v0.3.0 retrospective.

**Two changes it needs before it goes out.**

**1. It should carry the Part 1 result.** The post's own closing argument is that
"a narrow rule with a stated reach is worth more than a broad one with unstated
failure modes." Three subsequent narrowings at zero measured false-positive cost
is a direct, quantified confirmation of exactly that thesis — stronger than the
ten-point delta the post currently leads with, because it is evidence about the
*shape* of the rule rather than a single measurement. It arrived after the post
was drafted, which is why it reads as absent rather than omitted.

**2. It should be a v0.3.1 post, not a v0.3.0 post.** This is the part that
matters for honesty rather than strength. The post states the rule as "the call
is allowed if **every** recipient is the author of the tainted source." In
v0.3.0 the implementation did not hold that: `Customer <customer@example.com>,
attacker@evil.example` compared only the bracketed span, and a declared recipient
array silently dropped non-string elements. Both are closed in 0.3.1.

Publishing it as-is would state a guarantee that the version under discussion
did not fully enforce. The fix is small and improves the piece: the gap and its
closure are the same *kind* of finding the post is already built around — the
inversion that turns a safety mechanism into an exfiltration channel — and the
post already has the vocabulary for it. Reframe to 0.3.1, and let the recipient
gap sit alongside the content-searching formulation as the second thing that
looked correct and was not.

Nothing else in the post is falsified. The author-side asymmetry argument
(§17.2) — attacker-controlled body versus source-asserted field, and the
deliberate absence of any content-searching function — is accurate as written and
still true of the current tree.

---

## Part 5 — not assessed

Two items raised elsewhere are outside what this review examined, and are
recorded here only so they are not assumed covered:

- **Branch protection on `main`.** A repository-settings decision, not a code
  finding. Not evaluated.
- **Publishing cadence, and the "five operator messages."** No basis to assess —
  the operator-message set is not something this review inspected, and "#1" is
  not identifiable from the tree. If those should be reviewed, they need to be
  named.

---

## Suggested order

1. **F2**, if the diagnostic is wanted — one optional ledger field, the only item
   an operator would notice, and 0.3.1 is the release that makes it valuable.
2. **F1** alongside it, since F2 forces the decision about where
   `RecipientsUndeclared` is produced anyway.
3. **Tag 0.3.1.** Nothing above blocks it.
4. **The two architectural-drift items** as the first commit after the release —
   one refactor, no behaviour change.
5. **The post**, reframed to 0.3.1 and carrying the Part 1 result.
6. **0.4.0:** `env` passthrough, cwd, approval durability, `verify` continuation,
   streaming reads.
