# Security

Bulkhead is a security tool, so it owes you a precise account of what it does
and does not defend against. This document is that account. `DESIGN-v2.md` holds
the full threat model; this is the operator-facing summary, kept honest.

**Applies to:** v0.1.0 (Phase 0). Pre-1.0 and not yet production-hardened.

## What Bulkhead enforces today

| Property | Mechanism |
| --- | --- |
| An upstream cannot silently change a tool's definition | Definitions are pinned at first sight; a changed definition is **withheld** — never served — until an operator runs `bulkhead repin <server>` |
| A mediated call cannot reach Bulkhead's own files | Compiled-in invariants deny any call whose path-like argument resolves into the Bulkhead home directory, the binary, or the active config |
| The audit trail cannot be read or edited through the proxy | The ledger is append-only and lives inside the protected home directory |
| Enforcement is deterministic | No model call, no network access, and no nondeterminism anywhere in the decision path |

Both properties are demonstrated by runnable scripts: `./demo/run.sh` and
`./demo/run_rugpull.sh`. Both assert their own security property and fail loudly
if it regresses.

## Not implemented yet (Phase 1)

Bulkhead's headline goal — *untrusted input must not reach a sensitive sink* — is
**not yet enforced**. v0.1.0 is a reference monitor with self-protection and
metadata pinning; it passes tool calls through otherwise. Specifically absent:

- **Taint tracking and provenance matching** (R3). Nothing today prevents
  tainted content from flowing to an exfiltration sink.
- **Capability profiles** (R2) — per-server network/filesystem/exec confinement.
- **Consent / escalation.** Decisions are Allow or Deny; there is no `Escalate`.
- **Mediation beyond tools.** Only `tools/call` and `tools/list` are mediated.
  Resources, prompts, sampling, Tasks and MCP Apps are **not** — they are neither
  inspected nor deliberately refused yet.

Do not deploy v0.1.0 expecting exfiltration protection. It does not have any.

## Known limitations (by design, not bugs)

These are structural. They are not scheduled to be "fixed", because the fix
belongs at a different layer or does not exist at this boundary.

### Path checks are advisory: inode aliases and TOCTOU

Self-protection identifies protected files **by path**. Canonicalization resolves
symlinks, `..`, and `~`, but two things escape it:

- **Inode aliases.** A hardlink to a protected file, or a bind mount of the
  Bulkhead home, is a *second real name* for the same data. It resolves outside
  every protected root, so it is allowed, and reading it returns the protected
  file's contents.
- **Time-of-check/time-of-use.** Bulkhead checks a path and then forwards the
  call; the *upstream server* opens the file moments later. The filesystem can
  change in between.

Checking `(st_dev, st_ino)` instead of paths would not close either hole:
not-yet-existing targets have no inode (and denying writes to files that do not
exist yet is required), and TOCTOU is unfixable by any component that does not
itself hold the file descriptor.

**Why this is acceptable:** creating such an alias *through a mediated call* is
itself denied, because the call must name the protected path as its source. So
exploiting this requires filesystem access outside MCP — and an attacker with
that access can simply read the file directly. It grants no capability the
malicious-host case does not already grant.

**Bulkhead is not a sandbox.** Kernel-level mechanisms (Landlock, Seatbelt,
containers) enforce filesystem confinement atomically and handle aliasing
natively. Pair Bulkhead with one for hostile-host threat models. As defense in
depth, run Bulkhead's state under a different OS user than your filesystem
servers.

### Path-like arguments are identified heuristically

An argument is treated as a path if it starts with `~` or contains `/`. This
catches absolute paths, relative paths, traversal, and symlinks — including paths
nested inside arrays and objects. It does **not** catch bare filenames with no
separator, or paths hidden inside encoded or base64 blobs. Per-server argument
schemas (which would remove the guesswork) arrive with capability profiles.

### Metadata pinning is startup-scoped and tools-only

Definitions are checked when Bulkhead connects to an upstream. A server that
mutates its definitions *mid-session*, without a reconnect, is not currently
re-checked. Pinning also covers tools only — `resources/list` and `prompts/list`
are not pinned, because those surfaces are not yet mediated.

### Out of scope entirely

A malicious client or compromised host OS; attacks that live purely in model
output and never reach a mediated call; semantic laundering, where a model
re-expresses tainted content in its own words (an implicit flow invisible at any
boundary); multi-tenant policy distribution.

## Reporting a vulnerability

Please report privately via GitHub's private vulnerability reporting rather than
a public issue. Findings that show a mediated call reaching Bulkhead's own state,
or a changed tool definition being served without an explicit re-pin, are the
most valuable — those are the properties v0.1.0 actually claims.
