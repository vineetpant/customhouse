---
title: "Blocking prompt injection deterministically costs 40% false positives. Here's what they actually were."
permalink: /false-positives/
---

# Blocking prompt injection deterministically costs 40% false positives. Here's what they actually were.

I built an MCP proxy that blocks prompt-injection exfiltration without looking at content. It works: 11 out of 11 injection scenarios blocked. It also blocked 4 of the 10 benign workflows that used a sink.

That second number is the interesting one, and I couldn't find anyone who had published theirs. So here is mine, and what happened when I went through the failures one by one.

## The rule

The proxy sits in front of all your MCP servers. Each upstream is declared trusted or untrusted. The moment a session receives a result from an untrusted server, calls that move money or send data out are refused for the rest of that session.

That's the whole mechanism. No model in the decision path, no pattern matching, no content inspection at all. The decision is a pure function of where data came from.

The appeal is that it can't be evaded by rewriting the payload. Signature-based detection has to be updated forever and still misses the attack nobody wrote a rule for. Provenance doesn't care how the injection is worded, encoded, translated or summarised: if the session touched an untrusted source, the sink is closed.

The cost is that provenance is a coarse signal. Which brings us to the 40%.

## What the false positives actually were

I expected these to be noise: cases where the taint was technically present but the flow was harmless. I was wrong, and the way I was wrong changed my roadmap.

All four blocked workflows involved genuine untrusted-to-sink data flow. The proxy was correct about the flow every single time. Content read from an untrusted source really was on its way to a sink.

What made them legitimate was not the data. It was the destination.

The clearest case: an agent reads a support ticket (untrusted, because a stranger wrote it), then sends a reply. Untrusted content in, external send out. That is exactly the shape of an exfiltration attack. The only thing distinguishing it is that the reply goes back to the person who wrote the ticket.

At the tool boundary, those two situations are identical. Same source, same sink, same data flow. The difference lives entirely in who receives it.

## Why this matters more than the number

My assumption before doing the analysis was that finer granularity would fix it. Track which values came from untrusted sources, fingerprint them, and only block calls whose arguments actually carry that data.

Going through the four cases killed that idea. Fingerprinting would have confirmed all four blocks, not cleared any of them. The untrusted data genuinely is in the arguments. Finer tracking of the flow tells you nothing new, because the flow was never the problem.

The fix has to be destination classification: distinguishing a reply going back to the author of the untrusted content from a third-party recipient introduced by that content.

And that distinction has a trap in it. The naive version, "recipient appeared in the untrusted input, so it's fine", is exactly backwards for the classic exfiltration shape, where the attacker embeds their own address in the poisoned content and the agent sends data there. The rule has to be that the recipient is the *author* of the tainted artifact, checked structurally against the sender field, not merely that the recipient appears somewhere in it. Get that boundary wrong and the false-positive fix becomes the vulnerability.

## The per-class breakdown

The aggregate number hides the useful structure:

| Sink class | Benign attempts | Blocked |
|---|---|---|
| payment / transfer | 1 | 0 |
| external send | 7 | 3 |
| data egress | 2 | 1 |

Money movement produced no false positives at all. Nothing in the benign workflows legitimately needed to transfer funds after reading untrusted content. So that class can bear a hard block with no usability cost.

Sending and uploading cannot. Those get an approval path instead: the call is refused with instructions, and an operator authorises one retry from a terminal. The agent can't grant it to itself.

Those defaults are measured rather than guessed, which I think is the actual argument for publishing a false-positive rate. Without the breakdown, 40% is just a discouraging number. With it, it tells you which enforcement mode each class should ship with.

## What I'd tell anyone building this

Publish both numbers. A block rate on its own is unfalsifiable: every guard blocks everything if you don't measure what else it blocks. The tools I surveyed publish neither.

Then read your own false positives individually rather than treating them as a rate to optimise. The rate told me my approach was too coarse. The four cases told me *which* refinement would help and which one I'd have wasted a month on.

The proxy is Rust, Apache-2.0, and the scenario suite regenerates both numbers with one script: [github.com/vineetpant/customhouse](https://github.com/vineetpant/customhouse)

I'm most interested in failure modes I haven't found, particularly whether untrusted content can be laundered through a trusted server so the session never gets tainted at all.
