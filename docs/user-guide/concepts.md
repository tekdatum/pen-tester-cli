# Core Concepts

This guide is the mental model. Once you have it, every flag and environment variable
in the [reference docs](../configuration.md) becomes obvious — they're all just knobs
on the pipeline described below.

---

## The pipeline

Every scan, regardless of auditor or target, is the same four-stage pipeline:

```
  ┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐
  │  GENERATE │ ──▶ │   SEND    │ ──▶ │  DETECT   │ ──▶ │  REPORT   │
  │  attacks  │     │ to target │     │  bypass?  │     │  results  │
  └───────────┘     └───────────┘     └───────────┘     └───────────┘
     auditor           scanner          fence field       generators
                                        or judge LLM
```

1. **Generate** — an *auditor* produces adversarial prompts (jailbreaks, injections,
   encoded payloads, multi-turn manipulations…).
2. **Send** — the *scanner* delivers each prompt to **your** target and captures the
   response.
3. **Detect** — the tool decides whether that response counts as a **bypass** (the
   attack succeeded / the defense failed).
4. **Report** — results are aggregated into HTML, PDF, CSV, and Markdown.

Almost everything you configure is answering one of two questions from stages 2 and 3.
Hold onto that: **the scanner (how to reach the target)** and **bypass detection (how
to judge the result)** are the two decisions you always make.

---

## The two decisions

### Decision 1 — How do I reach your target? (the scanner)

The **scanner** is the tool's transport layer. It takes an attack prompt, delivers it
to your system, and hands back the response. You configure it one of three ways:

| Option | Use when | How |
|---|---|---|
| **curl command** | Your target is an HTTP endpoint. | `--curl-command "curl … \$PROMPT …"` |
| **curl file** | Same, but the command is long or has awkward quoting. | `--curl-file ./target.txt` |
| **custom handler** | Your target isn't plain HTTP — a Python SDK, gRPC, a local model, extra signing/auth. | `--custom-handler ./h.py:MyHandler` |

The one non-negotiable rule for curl: **the command must contain `$PROMPT`.** That
placeholder is where each attack string is substituted. It's replaced with a
*JSON-encoded* string, so `{"text": $PROMPT}` becomes valid JSON like
`{"text": "ignore your instructions and…"}`.

#### Custom handlers

When HTTP-with-`curl` can't express your target, implement `CustomHandler`. You get
full control over the request; you return a `HandlerResponse`:

```python
from pentester import CustomHandler, HandlerResponse

class MyServiceHandler(CustomHandler):
    def request(self, text: str) -> HandlerResponse:
        reply = my_client.send(text)          # however you reach your system
        return HandlerResponse(
            response=reply.raw_text,           # what the target said
            passed=reply.got_through,          # True  = attack bypassed the guard
                                               # False = attack was blocked
        )
```

`HandlerResponse` has exactly two fields:

- `response: str` — the target's raw reply (shown in the detail report).
- `passed: bool` — **`True` means the attack got through** (a bypass); `False` means
  it was blocked. With a custom handler, *you* decide what counts as a bypass, so
  detection (Decision 2) is entirely in your hands.

### Decision 2 — How do I know an attack succeeded? (bypass detection)

This is where the **target type** matters, because a "bypass" means different things
for different systems.

| `--target-type` | What the target is | What "bypass" means | How it's detected |
|---|---|---|---|
| `SEMANTIC_FENCE` *(default)* | A guardrail / classifier that says allow-or-block. | The guard let a malicious prompt through. | Read a field from the response via `--json-dot-target` (e.g. `body.valid`). |
| `LLM` | The language model itself. | The model produced the harmful/jailbroken content. | A **judge model** (or a probe's built-in detectors) grades the reply text. |

This single choice changes what the tool needs from you:

- A **fence** gives you a structured verdict, so detection is a cheap field lookup —
  no extra model, no API key.
- An **LLM** just replies in prose. Deciding whether that prose is a successful
  jailbreak requires *judgment*, which is why LLM mode needs a judge model (see next
  section) and, for some auditors, a way to extract the reply text
  (`PENTESTER_SCANNER__RESPONSE_TEXT_TARGET`, e.g. `body.choices.0.message.content`).

#### Detecting a bypass

For a fence, `--json-dot-target` is a dotted path into the response:

```
response body:  { "result": { "blocked": false } }
json-dot-target: body.result.blocked
```

The value at that path is coerced to a boolean and recorded as `bypassed`. Pick the
field whose truthiness means "the attack succeeded." If your field means the opposite
(e.g. `blocked: true` when *safe*), you'll want a custom handler where you can invert
it, or an endpoint field that reads the way you need.

---

## The judge is not the target

This trips up almost everyone, so it gets its own section.

There are up to **three different models** in play, and confusing them causes most
configuration mistakes:

| Role | What it is | Configured by |
|---|---|---|
| **Target** | The system under attack. | The **scanner** (curl/handler). Only when `--target-type LLM` is the target itself a model chosen via `PENTESTER_LLM__*`. |
| **Judge / scorer** | Grades whether a reply is a bypass (LLM mode). | `PENTESTER_LLM__PROVIDER` + `PENTESTER_LLM__MODEL` + the matching API key. |
| **Attacker** | Drives multi-turn jailbreaks (some strategies). | Strategy-specific settings; also needs an API key. |

The key insight: **`PENTESTER_LLM__*` and your `OPENAI_API_KEY` usually configure the
*judge*, not the target.** Your target is reached through the scanner. The API key
pays for the model that *scores* the attack — except in the special case where the
target type *is* `LLM` and you want the tool to call the model directly.

```bash
PENTESTER_LLM__PROVIDER=openai   # provider for the JUDGE
PENTESTER_LLM__MODEL=gpt-4o-mini # model for the JUDGE
OPENAI_API_KEY=sk-...            # pays for the JUDGE
```

| Provider | API key |
|---|---|
| `openai` | `OPENAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `gemini` | `GEMINI_API_KEY` |

---

## The auditors

An **auditor** is an adapter around a third-party red-teaming framework. Each brings a
different library of attacks. You choose them with `--auditors` (default: all four).

| Key | Framework | Strong at |
|---|---|---|
| `garak` | [garak](https://github.com/leondz/garak) | Breadth — 50+ probe families: DAN jailbreaks, known-bad signatures, prompt injection, encoding tricks. |
| `pyrit` | [PyRIT](https://github.com/Azure/PyRIT) (Microsoft) | Multi-turn strategies: Crescendo, Red Teaming, Tree of Attacks with Pruning. |
| `inspect_ai` | [Inspect AI](https://inspect.aisi.org.uk/) (UK AISI) | Standardized benchmarks: StrongREJECT, B3, Fortress, AgentHarm, AgentDojo. |
| `promptfoo` | [Promptfoo](https://promptfoo.dev/) | Config-driven probing; rich multi-turn strategies (crescendo, goat, hydra…). |

Auditors run independently. **If one fails, the others still run and still report** —
the orchestrator catches the error, logs it, and moves on. A failed auditor simply
contributes no results, so an empty section in a report usually means "that auditor
errored," not "no attacks succeeded." Check the terminal logs.

Each auditor has per-auditor knobs (which probes/datasets/benchmarks, its own
`MAX_ATTACKS` cap that overrides the global one, multi-turn toggles). Those live in
the per-auditor reference docs: [garak](../auditors/garak.md),
[PyRIT](../auditors/pyrit.md), [Inspect AI](../auditors/inspect_ai.md),
[Promptfoo](../promptfoo.md).

---

## Isolation: why garak has its own environment

garak pins dependencies that can clash with the rest of the stack, so the tool runs it
inside a **dedicated virtual environment** (`pentester_garak_env/`), as a subprocess.
Your settings are serialized in, results are serialized back out, and results arrive as
the same result objects as every other auditor — the isolation is invisible except for:

- a **slow first run** while the environment is built (one-time), and
- a `pentester_garak_env/` folder appearing in your working directory.

The environment is rebuilt only when its pinned package set changes. Full mechanism:
[Venv isolation](../auditors/venv.md).

---

## Reports

The reporting stage fans the aggregated results out into every format you asked for
(`--generator-keys`, default all four). For each run it writes:

- **`summary.<ext>`** — counts and pass/bypass rates across the whole run and per
  auditor. The executive view.
- **`<auditor>_details.<ext>`** — every individual attack: the prompt, the response,
  and the verdict. The investigative view.

Layout, formats, and how the numbers are computed: [Reporting](../reporting.md).

---

## Putting it together

Given all of the above, reading a command like this becomes trivial:

```bash
PENTESTER_LLM__PROVIDER=openai PENTESTER_LLM__MODEL=gpt-4o-mini OPENAI_API_KEY=sk-... \
pentester \
  --target-type LLM \
  --auditors garak,pyrit \
  --curl-command "curl … {\"messages\":[{\"role\":\"user\",\"content\": \$PROMPT}]} …" \
  --generator-keys html,pdf
```

You can now name every piece: target type = LLM (so a **judge** grades replies, hence
the `PENTESTER_LLM__*` + key), the **scanner** reaches an OpenAI-style endpoint, two
**auditors** generate the attacks, and two report formats come out. That's the whole
model.

Next: [A Full Run](./full-run.md) exercises all of this against real targets.
