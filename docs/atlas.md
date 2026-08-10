# Sentinel → MITRE ATLAS mapping

[ATLAS](https://atlas.mitre.org/) is the AI-systems analogue of ATT&CK: the
same shared-adversary-vocabulary idea, for attacks on machine-learning and
autonomous-agent systems. Sentinel is a *runtime* guard, so its coverage is
narrow by design: it defends the **behavioral layer** — what the agent does
with its tools, network, and files — not the prompt layer.

## Protection → ATLAS technique

| Sentinel protection | What it does | ATLAS technique covered |
| --- | --- | --- |
| External-egress deny | Denies the agent tree from holding connections to public addresses | **AML.T0086** — Exfiltration via AI Agent Tool Invocation |
| Blocklist host rules | Flags/denies connections to known-bad endpoints | AML.T0086 (exfil destination) / AML.T0051.001 (indirect injection C2 leg) |
| Sensitive-write detection | Flags writes to `.env`, `id_rsa`, `*.pem`, credential stores | AML.T0084 — Exfiltration via AI Tool Data Theft (harvesting stage) |
| Process-tree observation | Watches the agent's spawned children for known-bad binaries | AML.T0110 — AI Agent Tool Poisoning (compromised tool behavior) |
| Kill-switch | Terminates the agent tree on deny | (containment control, not a technique — the *response* to any AML.T#### chain) |
| Policy: `deny > flag > allow` | Deterministic verdict precedence | (control — the enforcement backbone for the techniques above) |

## What Sentinel does NOT cover (honest scope)

| ATLAS technique | Why it's out of scope today |
| --- | --- |
| AML.T0051 — LLM Prompt Injection (direct) | A *text* attack; Sentinel watches behavior, not prompts. Prompt filters are a different layer (and see [runtime-vs-prompt.md](runtime-vs-prompt.md) for why behavior matters anyway) |
| AML.T0051.001 — Indirect Prompt Injection | Partially covered: Sentinel catches the *result* (agent exfiltrating/executing) but not the poisoned context itself |
| AML.T0020 — Poison Training Data | Pre-runtime; attacks the weights, not the agent process |
| AML.T0024 — Exfiltration via Inference API | API-side; Sentinel is host-side by design |
| AML.T0070 — Privilege Escalation via PI | Partial: process-tree observation surfaces the agent spawning high-priv children |

## The placement argument

A runtime guard sits **between** the prompt layer and the impact layer:

```text
Prompt layer (filters, classifiers)  ── text in ──>  agent runtime
                                                       │
                                Sentinel (this repo) ──┤  allow / flag / deny
                                                       │
Impact layer (tools, network, files)  <──── actions ───┘
```

Filters answer "is this text safe to read?". Sentinel answers "is this
behavior safe to let happen?" — and when the answer is no, it can
**stop the action at runtime**, which no prompt filter can do.
