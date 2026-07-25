# Bulkhead

Deterministic enforcement at the MCP tool boundary.

Most agent security is **antivirus**: it scans for bad stuff before you install a
tool. Bulkhead is the **firewall**: it sits in the live traffic and enforces the
rule that untrusted input can't drive sensitive output.

Bulkhead is an aggregating proxy that sits between an agent client and its
upstream MCP servers, acting as a deterministic reference monitor. Its hard
constraint: **no LLM/model call and no network access exists anywhere in the
enforcement path — policy evaluation is a pure function.**

See [`DESIGN-v2.md`](./DESIGN-v2.md) for the full design and threat model.

## Status

Pre-release, under active development. Currently building **Phase 0** — the
passthrough aggregating proxy (namespacing, ledger, compiled-in self-protection
invariants; policy hardwired to allow).

## Build

```sh
cargo build
cargo test
```

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
