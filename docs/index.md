---
title: Customhouse
---

# Customhouse

Customhouse is an MCP proxy that blocks prompt-injection exfiltration without
inspecting content. Every upstream server is declared trusted or untrusted; once
a session receives a result from an untrusted server, calls that move money or
send data out are refused for the rest of that session. No model sits in the
decision path and no payload is ever pattern-matched, so the block cannot be
evaded by rewording, encoding or summarising the injection.

Source, demos and the measured block/false-positive rates:
[github.com/vineetpant/customhouse](https://github.com/vineetpant/customhouse).

## Writing

- [Blocking prompt injection deterministically costs 40% false positives. Here's what they actually were.](/false-positives/)
