# A Full Run

[Getting Started](./01-getting-started.md) ran one auditor with a hard cap. This guide
runs the tool the way you would for a real assessment: **all four auditors**, against
**both kinds of target**, producing **every report format** — then reads the output
properly.

It assumes you've read [Core Concepts](./02-concepts.md). If a term here is unfamiliar
(scanner, target type, judge, bypass), that's the page to check.

---

## What we'll do

1. [Set up configuration once](#1-set-up-configuration-with-an-env-file) with a `.env` file.
2. [Full run against a semantic fence](#2-full-run-against-a-semantic-fence) — all four auditors.
3. [Full run against an LLM](#3-full-run-against-an-llm) — with a judge model.
4. [Read the reports](#4-read-the-reports-properly) properly.
5. [Tune scope and cost](#5-tune-scope-and-cost) so real runs stay affordable.

---

## 1. Set up configuration with an `.env` file

For a real run you'll set many values. Passing them all as flags every time is
error-prone, so put the stable ones in a `.env` file at your working directory. The
tool loads `.env` (shared) then `.env.local` (personal overrides) automatically;
CLI flags override both.

Create `.env`:

```bash
# --- What we're testing -------------------------------------------------
PENTESTER_TARGET_TYPE=SEMANTIC_FENCE

# --- How to reach the target -------------------------------------------
PENTESTER_SCANNER__CURL_COMMAND=curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{"text": $PROMPT}'
PENTESTER_SCANNER__JSON_DOT_TARGET=body.valid

# --- Where reports go ---------------------------------------------------
PENTESTER_REPORTING__OUTPUT_DIR_PATH=./reports
PENTESTER_REPORTING__GENERATOR_KEYS=html,pdf,csv,markdown

# --- Judge model (needed by some auditors; see step 3) ------------------
PENTESTER_LLM__PROVIDER=openai
PENTESTER_LLM__MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-...
```

> **Secrets live in `.env.local`, not `.env`.** Put `OPENAI_API_KEY` and friends in
> `.env.local` and add it to `.gitignore` so you never commit a key. `.env.local`
> overrides `.env`, so it's the right place for machine- and person-specific values.

Every variable here has a matching CLI flag; the full mapping is in
[Configuration](../configuration.md).

> **Want a ready-made file for your scenario?** [Configuration Recipes](./04-env-examples.md)
> has complete, copy-pasteable `.env.local` files: a fence smoke test, an LLM target, and
> a master file with every auditor and setting.

> **Watch the value formats.** In a `.env` file, *list* settings must be JSON arrays
> (`PENTESTER_AUDITORS=["garak","pyrit"]`), not comma-separated — that form only works
> on the `--auditors` flag. Details in [Configuration Recipes](./04-env-examples.md#how-values-are-formatted-read-this-first).

---

## 2. Full run against a semantic fence

With the `.env` above in place, the fence run is just:

```bash
pentester
```

No flags — it reads everything from `.env`, and with no `--auditors` it runs **all
four**. Here's what to expect from each, and where it can trip up:

| Auditor | Needs an API key for a fence run? | Notes |
|---|---|---|
| `garak` | No | First run builds `pentester_garak_env/` (one-time, slow). Reads bypass from the fence field. |
| `pyrit` | No (single-turn) | Multi-turn strategies need an attacker key — see [step 5](#5-tune-scope-and-cost). |
| `inspect_ai` | Sometimes | Benchmarks that grade with a model use the judge from `PENTESTER_LLM__*`. |
| `promptfoo` | Special | Runs the external `promptfoo` CLI as a subprocess and may need network access + a registered email. See the callout below. |

> **Promptfoo prerequisites.** The `promptfoo` auditor shells out to a `promptfoo`
> command that ships with the pip dependency, and its red-team generation reaches a
> remote service, so that run needs **network access**. Promptfoo also asks for a
> registration email; the tool sets a default automatically.

Before any auditor runs, the tool **pre-flights the scanner** — it verifies the target
is reachable. If your curl command is wrong or the endpoint is down, you'll get a clear
error here rather than a confusing failure deep in a scan.

### Smoke-test first

A full four-auditor run is not fast. On the *first* run of a new target, prove the
wiring with a tiny scan before committing to the real thing:

```bash
pentester --auditors garak --max-attacks 3
```

If that produces a sane report, your scanner and detection are wired correctly. Now
scale up.

---

## 3. Full run against an LLM

Testing a raw LLM (rather than a fence) changes **how bypass is detected**: there's no
allow/block field, so a **judge model** grades each reply. Two things change from the
fence setup.

**a) Set the target type to `LLM`** and point the scanner at the model's endpoint. In
LLM mode there's no `--json-dot-target`; instead you tell the tool how to pull the
*reply text* out of the response, so the judge has something to grade:

```bash
# .env additions / overrides for an LLM target
PENTESTER_TARGET_TYPE=LLM
PENTESTER_SCANNER__CURL_COMMAND=curl https://api.openai.com/v1/chat/completions -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-...' --data-raw '{"model":"gpt-4o-mini","messages":[{"role":"user","content": $PROMPT}]}'
PENTESTER_SCANNER__RESPONSE_TEXT_TARGET=body.choices.0.message.content
```

`RESPONSE_TEXT_TARGET` is a dotted path (like `json-dot-target`) but it extracts the
model's **text**, e.g. `body.choices.0.message.content` for OpenAI-style responses.
Some auditors (garak's LLM-via-scanner mode, PyRIT multi-turn) require it.

**b) Provide the judge.** The `PENTESTER_LLM__*` values and API key from step 1 are the
judge — the model that decides whether a reply is a jailbreak. (Re-read
[The judge is not the target](./02-concepts.md#the-judge-is-not-the-target) if that split
feels fuzzy.)

Run it:

```bash
pentester
```

> You can also let the tool call a provider's model **directly** as the target (no
> curl) by setting `--target-type LLM` with `PENTESTER_LLM__MODEL` and no scanner.
> The per-auditor docs (e.g. [garak](../auditors/garak.md#examples)) show that form.

---

## 4. Read the reports properly

After a run, `./reports/` (from our `OUTPUT_DIR_PATH`) looks like:

```
reports/
└── 20260717_143012/          ← one folder per run, timestamp = YYYYMMDD_HHMMSS
    ├── html/
    │   ├── summary.html
    │   ├── garak_details.html
    │   ├── pyrit_details.html
    │   ├── inspect_ai_details.html
    │   └── promptfoo_details.html
    ├── pdf/
    ├── csv/
    └── markdown/
```

Read them in this order:

1. **`summary.*` — the verdict.** Total attacks, how many bypassed, broken down by
   auditor. This answers "how did the target do?" at a glance. Start here every time.

2. **`<auditor>_details.*` — the evidence.** One row per attack: the prompt sent, the
   target's response, and whether it was a bypass, grouped by attack category and type.
   Open the details for whichever auditor reported bypasses to see exactly which
   attacks worked. This is what you hand to whoever fixes the target.

Two things worth internalizing:

- **A missing `<auditor>_details` file means that auditor produced no results** — most
  often because it errored (see the terminal logs), not because nothing got through.
  The other auditors still ran; failures are isolated.
- **Pick formats for the audience.** `html`/`pdf` for humans and reports; `csv` for
  slicing in a spreadsheet or a script; `markdown` to paste into a ticket or wiki.
  Control the set with `--generator-keys` / `PENTESTER_REPORTING__GENERATOR_KEYS`.

Report internals and how rates are computed: [Reporting](../reporting.md).

---

## 5. Tune scope and cost

Full, uncapped runs across four frameworks can be slow and — when a judge or attacker
model is involved — expensive. The main levers:

### Cap the number of attacks

Global cap, with per-auditor overrides that take priority:

```bash
# .env
PENTESTER_MAX_ATTACKS=50          # applies to every auditor…
PENTESTER_GARAK__MAX_ATTACKS=200  # …except garak, which gets 200
```

### Narrow what each auditor runs

Instead of the full default set, target specific attack families:

```bash
# garak: only these probe classes
PENTESTER_GARAK__PROBES=["probes.dan.Dan_6_2","probes.knownbadsignatures.EICAR"]

# pyrit: only these datasets
PENTESTER_PYRIT__DATASET_NAMES=["xstest"]
```

### Enable multi-turn deliberately

Multi-turn strategies (Crescendo, GOAT, Tree of Attacks…) use an **attacker LLM** to
carry a jailbreak across several turns. They are slower and cost API calls — and they
**always need an LLM key, even against a fence.** They're opt-in for that reason:

```bash
# pyrit
PENTESTER_PYRIT__ENABLE_MULTITURN=true
PENTESTER_PYRIT__ATTACK_STRATEGIES=["crescendo","tree_of_attacks"]

# promptfoo
PENTESTER_PROMPTFOO__ENABLE_MULTITURN=true
PENTESTER_PROMPTFOO__MULTITURN_STRATEGIES=["crescendo","goat"]
```

The full set of per-auditor knobs — every dataset, benchmark, strategy, and cap — is in
the top-level [`README.md`](../../README.md#environment-variables) and the per-auditor
reference docs.

---

## You're done

You've run every auditor against both target types, produced all report formats, and
read the results. From here:

- Refine scope for your target using the levers in [step 5](#5-tune-scope-and-cost).
- Go deep on a specific framework: [garak](../auditors/garak.md) ·
  [PyRIT](../auditors/pyrit.md) · [Inspect AI](../auditors/inspect_ai.md) ·
  [Promptfoo](../auditors/promptfoo.md).
