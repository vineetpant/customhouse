# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries that change what Customhouse **allows or refuses** are marked
**(enforcement)**. Those are the ones to read on an upgrade: everything else can
change the experience, but only these change the guarantee.

## [Unreleased]

## [0.3.1] — 2026-08-20

A review pass over the v0.3.0 additions. Every item below was reproduced with a
test before being changed.

### Fixed

- **(enforcement) A recipient could hide a second party from the author-equality
  rule**, by two routes. Textually: `Customer <customer@example.com>,
  attacker@evil.example` is one string to Customhouse and an address *list* to a
  mail server, and v0.3.0 compared only the bracketed span. Structurally: a
  declared recipient array kept its string elements and silently dropped the
  rest, so `["customer@example.com", {"email": "attacker@evil.example"}]`
  contributed one recipient to the comparison and two to an upstream that
  accepts object recipients. Either way the exemption could authorise a send to
  a recipient it never examined.

  Both are closed the same way — a value that is not fully understood no longer
  produces a shorter list, it stops the exemption. Recipients now authorise only
  if every value identifies exactly one party (new `recipient_unparseable`
  reason), and a declared field holding anything but a string or an array of
  strings marks the whole set opaque. Requires an upstream configured with
  `author_field` and `recipient_fields`, so it affects opt-in deployments only.
  The measured block and false-positive rates are unchanged.
- **A ledger record truncated by a crash destroyed the next one.** A run that
  died mid-write left no trailing newline, so the next process appended directly
  onto the fragment and merged two records into one unreadable line. The
  fragment is now terminated on open and kept as evidence.
- **Ledger ids restarted at 0 each run, so one file could repeat them.** Ids are
  cited as references — `caused_by_call`, `server:call_id`, and the denial text's
  "call N" — which made all of those ambiguous in any file spanning more than one
  session. The counter now resumes from the file, as the hash chain already did.
- `customhouse init` skipped servers declared `"type": "stdio"` — the form Cursor
  and VS Code write for local servers — and reported them as "not a stdio
  server". Only a `url`, or a `type` that is not `stdio`, now marks a server
  unlaunchable.
- An author value that identifies nobody (`""`, `" "`, `"<>"`) is recorded as
  `author_unknown` rather than `authors_disagree`.
- `init`'s closing message no longer prints with ragged indentation.

### Changed

- `SECURITY.md` now discloses two ledger limits that were previously unstated:
  verification stops at the first unreadable line, so entries past it are
  unchecked; and the ledger fails open, so a running proxy does not guarantee a
  written trail.

## [0.3.0] — 2026-08-20

### Added

- **(enforcement) Destination classification.** In a session tainted by
  untrusted content, an `external_send` call is now allowed if every recipient
  is the **author** of the tainted source. Authorship is read only from a
  structured field the upstream declares (`author_field`), never by searching
  content — an attacker who writes a message body must not be able to forge the
  value that authorises a reply. Recipients are read from declared
  `recipient_fields`. If any taint source has no author, the sources disagree, or
  any recipient is a third party, the stricter session rule stands.
  This **relaxes** enforcement in one narrow case; see
  [`SECURITY.md`](./SECURITY.md) for the residual channel it opens.
- Hash-chained audit ledger. Every entry carries the SHA-256 of the previous
  line, so editing or removing an entry breaks every entry after it.
- `customhouse verify-ledger [path]` walks the chain and, on failure, exits
  non-zero naming the first bad line. Tamper-**evident**, not tamper-proof: an
  attacker with write access can recompute the whole chain. The limitation is
  stated in `SECURITY.md` and printed on success as well as failure.
- `customhouse init` generates a `customhouse.toml` from the MCP servers Claude
  Desktop and Cursor already launch. It never marks any upstream trusted, and
  names every server it skipped with the reason rather than omitting it
  silently. Refuses to overwrite an existing config without `--force`.
- `author_field` and `recipient_fields` on `[[upstream]]`.

### Changed

- Measured false-positive rate over benign workflows using a sink: **40% → 30%**
  (4/10 → 3/10), attributable to destination classification. Block rate holds at
  **100%** over a scenario set that grew from 11 to 12 — the added scenario
  plants the attacker's address in a poisoned body, which is the case a naive
  version of this rule would have allowed. Regenerate with
  `./demo/run_metrics.sh`.
- `/docs` (the GitHub Pages site) is excluded from the published crate.

## [0.2.1] — 2026-08-14

### Fixed

- `cargo install` added several binaries to a user's PATH. The demo mock
  servers moved to `examples/`, so only `customhouse` is installed.

## [0.2.0] — 2026-08-14

### Added

- **(enforcement) Cross-server flow enforcement.** Trust classes per upstream
  (default untrusted), a sink taxonomy (`payment_transfer`, `external_send`,
  `data_egress`), session taint, and the rule at the chokepoint: once an
  untrusted upstream's result enters a session, sink calls are refused for the
  rest of it — including sinks on a *different* upstream.
- `require_approval` mode and out-of-band `customhouse approve <sink-class>`,
  granting one single-use retry that expires after ten minutes. The agent cannot
  reach it: the approval store lives inside the self-protected home directory.
- Published block rate and false-positive rate in `METRICS.md`, regenerated by
  `./demo/run_metrics.sh`. The false-positive number is reported because a
  coarse rule has a cost, and hiding it would make the block rate unreadable.
- `Decision::Escalate`, with invariant escalation made unrepresentable in the
  type system — a self-protection invariant cannot ask for permission.

### Changed

- Renamed to **customhouse**.

## [0.1.0] — 2026-07-26

Never tagged and never published to crates.io; the project carried an earlier
name at this point. Recorded here because it is where the enforcement surface
below first existed.

### Added

- Aggregating MCP proxy: one endpoint fronting N upstream servers over stdio,
  with tools namespaced per upstream (`web__fetch`) and routing on that name.
- **(enforcement) Self-protection invariants**, compiled into the binary and
  evaluated before any configurable policy. Any mediated call whose path-like
  argument canonicalizes into the Customhouse home directory, ledger, pin store,
  binary or active config is denied. Not expressible or removable in config.
- **(enforcement) Tool-definition pinning.** Definitions are pinned at first
  sight; a changed definition is *withheld* — never served — until an operator
  runs `customhouse repin <server>`.
- Append-only JSONL audit ledger of every mediated call.
- Unmediated surfaces (resources, prompts) are explicitly refused rather than
  silently reported empty.

[Unreleased]: https://github.com/vineetpant/customhouse/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/vineetpant/customhouse/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/vineetpant/customhouse/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/vineetpant/customhouse/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/vineetpant/customhouse/commits/v0.2.0
