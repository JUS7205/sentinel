# Why a runtime guard beats a prompt filter

*The core argument behind Sentinel — written up because "explain it in one
page" is the interview question.*

## The claim

The industry's default defense for AI agents is **prompt-layer filtering**:
classify inputs, sanitize retrieved context, block "suspicious" text. Prompt
filters are useful, but they are not a security boundary. The real attack
surface of an autonomous agent is not what it *reads* — it is what it *does*.
Sentinel's premise: **defend the runtime, not the prompt.**

## Why prompt filters lose

1. **They defend the wrong invariant.** A prompt injection doesn't need to
   "break" a filter — it needs to get one tool call to happen. The attacker's
   goal is behavioral (exfiltrate a file, send an email, run a command), and
   behavior happens at the runtime layer. Text classification is upstream of
   the decision that matters.

2. **They are trivially evadable.** Encoding, whitespace games, obfuscation,
   and split-payload attacks all target the *representation* of text.
   Meanwhile the tool call the attacker wants — `send_email(to=...)` — is a
   structured, typed object. Structured objects are vastly easier to police
   than free-form text.

3. **They are a race you can't win.** New bypasses ship faster than filters
   learn them. A runtime policy is deterministic: the rule "no external
   egress" is true no matter how the instruction was phrased.

## What runtime enforcement buys you

| Property | Prompt filter | Runtime guard (Sentinel) |
| --- | --- | --- |
| Attack surface monitored | Text only | Process tree, network, filesystem |
| Evasion difficulty | Low (encoding, obfuscation) | High (behavior must actually change) |
| Actionable response | Rewrite / refuse (text-level) | **Kill-switch** (system-level) |
| Determinism | Probabilistic (classifier) | Deterministic (declarative policy) |
| Testable | Requires live LLM | Pure unit tests (snapshot in → verdict out) |

## The layered answer

This is not a "filter bad, runtime good" essay. The right architecture is
layered:

1. **Prompt layer** — reduce *successful* injections (classifiers, sanitizers).
2. **Runtime layer — Sentinel** — ensure the *impact* of any successful
   injection is bounded: no external egress, no sensitive writes, no
   known-bad binaries, no unbounded tool use.
3. **Response layer** — kill-switch + action log so a denial is also an
   investigation artifact.

Filters reduce the frequency of incidents. The runtime guard bounds the
blast radius of the ones that get through. Only the second one is a security
boundary; the first is risk reduction.

## The red-team validation

The `sentinel-red` repo runs this exact bet: four scripted attack primitives
(prompt injection, tool-output poisoning, indirect exfiltration, privilege
escape) against an undefended simulated agent — and every one is caught by the
policy at the action level, after the text has already slipped through any
imagined filter. That is the thesis, in test form.
