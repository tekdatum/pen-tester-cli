# Getting Started

This is the shortest path from "nothing installed" to "I have a report in front of
me." We'll install the tool, point it at a target, run a small scan, and open the
results. Later guides go deeper — this one just gets you a first win.

By the end you will have:

- Pentester CLI installed
- One auditor run against a target
- A report you can open in a browser

> **The mental model in one line:** an *auditor* generates attack prompts → the tool
> sends each one to *your target* → it checks whether the attack got through → it
> writes a report. If you want the full picture first, read
> [Core Concepts](./concepts.md). Otherwise, keep going — it'll make sense as we go.

---

## Prerequisites

| You need | Why | Check |
|---|---|---|
| **Python 3.11+** | The tool targets 3.11 and up. | `python --version` |
| **pip** | To install the package. | `pip --version` |
| **A reachable target** | Something to attack — an HTTP endpoint you can hit with `curl`. | see [Step 2](#step-2-describe-your-target) |
| *(optional)* An LLM API key | Only if your target is a raw LLM, or you use auditors that grade replies with a judge model. | [Core Concepts → The judge](./concepts.md#the-judge-is-not-the-target) |

You do **not** need an API key for the first scan below — a semantic-fence scan reads
its result straight from the target's response.

---

## Step 1 — Install

```bash
pip install pentester
```

Confirm the CLI is on your path:

```bash
pentester --help
```

You should see the list of options. If `pentester` isn't found, see
[Troubleshooting → command not found](./troubleshooting.md#pentester-command-not-found).

---

## Step 2 — Describe your target

Pentester CLI reaches your target with a **`curl` command that contains a `$PROMPT`
placeholder**. At scan time, `$PROMPT` is replaced with each attack string.

Here's a `curl` command for an imaginary guardrail endpoint. Note the two important
parts, called out below:

```bash
curl -X POST 'https://api.example.com/chat' \
  -H 'Content-Type: application/json' \
  --data-raw '{"text": $PROMPT}'
```

- `$PROMPT` — **required.** This is where each attack prompt is injected. No
  `$PROMPT`, no scan.
- The endpoint returns JSON. We need to tell the tool **which field says whether the
  attack got through** — that's the next step.

Suppose this endpoint responds like:

```json
{ "valid": true, "reason": "content allowed" }
```

If `valid: true` means "the guard let this through" (a bypass), then the field we care
about is `body.valid`. We pass that as `--json-dot-target "body.valid"`.

> `body.*` reaches into the JSON body; `headers.*` reaches into response headers.
> This dotted path is how the tool turns a raw response into a yes/no "bypassed"
> answer. More in [Core Concepts → Detecting a bypass](./concepts.md#detecting-a-bypass).

---

## Step 3 — Run your first scan

Start **small**: one auditor, a hard cap on the number of attacks. We use `garak`
because it needs no API key for a fence target.

```bash
pentester \
  --auditors garak \
  --max-attacks 5 \
  --json-dot-target "body.valid" \
  --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \$PROMPT}'"
```

What each flag does:

| Flag | Effect |
|---|---|
| `--auditors garak` | Run only the garak auditor (instead of all four). |
| `--max-attacks 5` | Send at most 5 attack prompts. Keeps this run fast and cheap. |
| `--json-dot-target "body.valid"` | Read `valid` from the JSON body to decide "bypassed". |
| `--curl-command "…"` | How to reach the target. `$PROMPT` is escaped as `\$PROMPT` so your shell doesn't expand it. |

> **Heads-up: the first garak run is slow.** garak runs inside its own isolated Python
> environment, which the tool builds on first use (folder `pentester_garak_env/`). This
> is a one-time step and can take a few minutes. Later runs reuse it and start fast.
> Why the isolation? See [Core Concepts → Isolation](./concepts.md#isolation-why-garak-has-its-own-environment).

Progress is logged to your terminal as the scan runs.

### Want it even faster?

Narrow garak to a single probe (attack family) instead of its full default set:

```bash
PENTESTER_GARAK__PROBES='["probes.dan.Dan_6_2"]' \
pentester \
  --auditors garak \
  --max-attacks 5 \
  --json-dot-target "body.valid" \
  --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \$PROMPT}'"
```

---

## Step 4 — Read the report

By default, reports land in `./output/`, organized by run timestamp and format:

```
output/
└── 20260717_143012/          ← one folder per run (YYYYMMDD_HHMMSS)
    ├── html/
    │   ├── summary.html       ← start here: pass/bypass counts across the run
    │   └── garak_details.html ← every prompt, its response, and the verdict
    ├── pdf/
    ├── csv/
    └── markdown/
```

Open the HTML summary in a browser:

```bash
open output/*/html/summary.html      # macOS
xdg-open output/*/html/summary.html  # Linux
```

- **`summary.*`** — the headline: how many attacks ran, how many bypassed, grouped by
  auditor. Read this first.
- **`<auditor>_details.*`** — the receipts: each individual prompt, the target's
  response, and whether it counted as a bypass. This is where you investigate a
  finding.

A **bypass** means the attack got through — the thing you're testing failed to stop
it. That's what you're hunting for.

> Only ran one auditor and want fewer files? Use `--generator-keys html` to generate
> just HTML. Full format list in [Reporting](../reporting.md).

---

## Step 5 — Where to go next

You've run a scan. Now:

- **Understand what just happened** → [Core Concepts](./concepts.md). Especially the
  difference between a *semantic fence* and an *LLM* target — it decides how bypass is
  detected.
- **Do it for real** → [A Full Run](./full-run.md) runs all four auditors against both
  a fence and an LLM, and covers judge-model setup.
- **Something broke?** → [Troubleshooting](./troubleshooting.md).

---

## Quick reference: the flags you'll use most

| Flag | Default | Purpose |
|---|---|---|
| `--curl-command` | – | How to reach the target (must contain `$PROMPT`). |
| `--curl-file` | – | Same, but read the curl command from a file (good for long/complex ones). |
| `--json-dot-target` | – | JSON path to the "bypassed" field (fence targets). |
| `--auditors` | all four | Comma-separated subset, e.g. `garak,pyrit`. |
| `--max-attacks` | none | Cap attacks per auditor. Great for smoke tests. |
| `--target-type` | `SEMANTIC_FENCE` | `SEMANTIC_FENCE` or `LLM`. |
| `--generator-keys` | all four | Report formats: `pdf,csv,html,markdown`. |
| `--output-dir-path` | `./output/` | Where reports are written. |

Full list: top-level [`README.md`](../../README.md) and [Configuration](../configuration.md).
