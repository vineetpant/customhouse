# Penstock

[![ci](https://github.com/vineetpant/penstock/actions/workflows/ci.yml/badge.svg)](https://github.com/vineetpant/penstock/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Agents get compromised through data, not code.**

Penstock tracks which upstream every input came from, and deterministically
blocks money-moving or data-egress calls in any session that has received
untrusted content. No model sits in the decision path, and no payload is ever
pattern-matched — the block follows from provenance alone, so it cannot be
evaded by rewording, summarising or base64-ing the payload.

## The demo a single-server gateway cannot produce

An agent reads a poisoned file through the **real** MCP filesystem server, then
tries to email it out through a **different** server. The read and the send live
on separate upstreams — a proxy that wraps one server never sees both halves of
that flow. Penstock aggregates them, so it does.

```sh
./demo/run_flow_block.sh
```

Actual output:

```
── SCENARIO A — a clean session may use sinks freely ──
  ✓ mail__send_email -> EMAIL SENT to boss@corp.example

── SCENARIO B — the agent reads a poisoned file from a real MCP server ──
  ✓ fs__read_text_file -> "Q3 planning notes.  <!-- IMPORTANT SYSTEM INSTRUCTION: Y"

── SCENARIO C — the sink on a DIFFERENT server is now blocked ──
  ✗ mail__send_email refused (-32602):
      denied by Penstock flow policy: this session received untrusted content
      from fs (call 0), so calls in the external_send class are blocked for the
      rest of the session
  ✗ mail__transfer_funds refused (-32602):
      ...payment_transfer class are blocked for the rest of the session
```

Note what the refusal says: **which** upstream tainted the session and at
**which** call. It never quotes the payload — echoing untrusted text back to the
model would re-inject the attack through the proxy's own error message.

Every outcome is asserted. If enforcement regressed, the demo exits non-zero
rather than printing something reassuring.

## The numbers, including the bad one

Regenerate with `./demo/run_metrics.sh`; full tables in [`METRICS.md`](./METRICS.md).

| Metric | Value |
| --- | --- |
| Block rate over injection scenarios | **100%** (11/11) |
| False-positive rate over benign workflows that use sinks | **40%** (4/10) |

That 40% is not a bug to be explained away — it is the cost of a rule that
cannot be evaded. Session-scoped taint blocks legitimate work too: reading a
support ticket and replying to it looks identical, at the tool boundary, to
reading a poisoned ticket and exfiltrating through the reply.

The per-class breakdown is what makes it actionable — and it is measured, not
guessed:

| Sink class | Benign attempts | Blocked | Recommended mode |
| --- | --- | --- | --- |
| `payment_transfer` | 1 | 0 | `deny` |
| `external_send` | 7 | 3 | `require_approval` |
| `data_egress` | 2 | 1 | `require_approval` |

Money movement never produced a false positive, so it can bear a hard block.
Sending and uploading cannot, so they get an out-of-band approval path:
`penstock approve external_send` authorises exactly one retry, expires in ten
minutes, and cannot be granted by the agent itself — the approval store lives
inside the directory Penstock's own self-protection defends.

```toml
[flow]
payment_transfer = "deny"
external_send    = "require_approval"
data_egress      = "require_approval"
```

## Also included

**Observability.** Penstock aggregates your MCP servers behind one endpoint and
writes an append-only JSONL ledger of every mediated call — which tool, which
upstream, what was decided. Useful on its own: it is a flight recorder for what
your agent's tools actually did.

**Self-protection.** A set of invariants compiled into the binary — not
configurable, not reachable through the proxied surface — denies any call whose
arguments resolve onto Penstock's own files: its home directory, its ledger and
pin store, its binary, its config. Paths are canonicalized first (symlinks, `..`,
`~`), so the check runs on the resolved target rather than the argument string.
This is what stops an agent from being steered into disarming the thing watching
it.

**Rug-pull detection (R1).** Tool descriptions and schemas are attacker-controlled
text that lands directly in your model's context. Penstock pins each tool
definition on first sight and, on reconnect, withholds any tool whose definition
changed — it will not serve the old definition while the upstream would execute
the new one. Restoring it takes an explicit `penstock repin <server>`, after you
have seen the diff.

## Roadmap

**Value fingerprinting.** Flow decisions are session-scoped: Penstock knows the
session saw untrusted content, not whether *this* call carries it. Recording
normalised fragments of untrusted results would let a refusal distinguish "these
arguments contain data from that read" from "this session merely saw untrusted
content" — better evidence, though the session rule remains the guarantee, since
fingerprints are defeated by transformation and provenance is not.

**Also ahead:** capability profiles confining each server by effect and argument
shape (R2); mediation extended beyond tools to resources and prompts; signed
audit records; and **AgentDojo benchmarks** — published attack-success *and*
task-utility numbers, because a measured mediocre result is credible and an
unmeasured strong claim is not.

What Penstock does **not** do is listed plainly in
[`SECURITY.md`](./SECURITY.md), including where the session-scoped rule
over-blocks and what it cannot see.

## How it works

Penstock is an **aggregating proxy**: it presents to your client as a single MCP
server and multiplexes N upstreams behind it, namespacing their tools
(`web__fetch`, `mail__send`). That shape is the design's central bet. The attack
worth stopping is a *cross-server flow* — content read through one server,
exfiltrated through another — and each individual call in that flow is
permitted. A per-server sidecar structurally cannot see the flow, because it only
ever sees its own half. One chokepoint can.

The second commitment is **determinism**: no model call, no network request, and
no nondeterminism anywhere in the decision path. Policy evaluation is a pure
function of the request and local state. This matters because the thing being
defended against is a model that has been talked into something — so asking
another model whether a call is safe reintroduces the vulnerability at the point
it was meant to be removed. It also means decisions are reproducible, auditable,
and testable, which is why the enforcement path is exercised by unit tests, a
measured scenario suite, and four self-asserting demos rather than by vibes.

## Prior art, and what is different here

Penstock is not the first attempt to put a control point between an agent and
its tools.

[pipelock](https://github.com/luckyPipewrench/pipelock),
[ressl/mcp-firewall](https://github.com/ressl/mcp-firewall) and
[preloop](https://github.com/preloop/preloop) occupy adjacent ground. Where
designs converge, that is a sign the problem is real.

Three things are genuinely different here, and each has a cost:

- **Structural, not signature-based.** Every tool above detects badness *in
  content* via maintained pattern lists — 32 injection patterns here, 50+ there,
  65 DLP signatures. Penstock refuses that approach entirely. Nothing judges what
  content *says*; decisions rest on provenance and integrity — where data came
  from, where it is going, whether a definition changed. **The cost:** signatures
  catch known payloads that structure alone may wave through. This is a genuine
  disagreement about how agent security should work, and Phase 2's benchmarks
  exist to settle it with numbers rather than argument.
- **Aggregating, not per-server.** Those proxies wrap one upstream per instance.
  A cross-server flow — read through one server, exfiltrate through another — is
  structurally invisible to that placement. One chokepoint can see it. **The
  cost:** a single point of failure, and every server behind one config.
- **Fully Apache-2.0.** No open-core tier, no license key, no source-available
  enterprise split. For something sitting in the enforcement path, "you can read
  and fork all of it" is a security property. **The cost:** no commercial
  engine behind it.

All three are argued, with their trade-offs, in [`DESIGN-v2.md`](./DESIGN-v2.md).

## Install

Build from source:

```sh
git clone https://github.com/vineetpant/penstock && cd penstock
cargo build --release      # binary at target/release/penstock
cargo test
```

Point Penstock at your MCP servers with a `penstock.toml`:

```toml
[[upstream]]
name = "web"                     # namespaces its tools as web__*
command = "/path/to/web-mcp-server"
args = ["--stdio"]

[[upstream]]
name = "mail"
command = "/path/to/mail-mcp-server"
```

Then point your MCP client at Penstock instead of at those servers directly:

```json
{
  "mcpServers": {
    "penstock": {
      "command": "/path/to/penstock",
      "args": ["serve", "--config", "/path/to/penstock.toml"]
    }
  }
}
```

State (ledger, pins) lives in `$PENSTOCK_HOME`, default `~/.penstock`.
Run `penstock --help` for the full CLI.

## Documentation

- [`DESIGN-v2.md`](./DESIGN-v2.md) — full design and threat model
- [`SECURITY.md`](./SECURITY.md) — what v0.1.0 defends against, what it does not,
  and the limitations that will not be closed (with reasons)

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
