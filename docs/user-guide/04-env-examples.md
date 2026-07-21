# Configuration Recipes (`.env.local` Examples)

Complete, copy-pasteable `.env.local` files for the most common scenarios. Every
recipe is a **whole file** you can drop in and run — not a fragment — and every value
format here has been verified against the settings loader, so they work as written.

> **The one rule that trips everyone up:** in a `.env` file, *list* settings must be
> written as **JSON arrays** (`["a","b"]`), not comma-separated. The comma-separated
> form (`garak,pyrit`) only works on the **CLI flag** (`--auditors`), not in the file.
> See [How values are formatted](#how-values-are-formatted-read-this-first) before you
> edit anything.

---

## How loading works

- The tool reads **`.env`** first, then **`.env.local`** — later wins. Put shared
  defaults in `.env` and **secrets/personal overrides in `.env.local`**.
- **`.env.local` should be git-ignored.** It holds API keys. Never commit it.
- **CLI flags override both files.** Anything you can put in a file, you can also pass
  as a flag for a one-off (e.g. `--max-attacks 5`).
- **Unknown variables are ignored**, so it's safe to keep unrelated vars in the file.

Create it:

```bash
touch .env.local
echo ".env.local" >> .gitignore
```

---

## How values are formatted (READ THIS FIRST)

Getting a value's *format* wrong is the #1 cause of a scan refusing to start. There are
four shapes:

| Shape | Looks like | Which settings |
|---|---|---|
| **Plain string** | `PENTESTER_LLM__MODEL=gpt-4o-mini` | curl commands, model names, paths, provider, dot-targets |
| **Boolean** | `PENTESTER_PROMPTFOO__ENABLE_MULTITURN=true` | anything `true`/`false` |
| **Comma string** | `PENTESTER_REPORTING__GENERATOR_KEYS=html,pdf` | **only** `GENERATOR_KEYS` (it's one string split later) |
| **JSON array** | `PENTESTER_AUDITORS=["garak","pyrit"]` | every *list* setting (see below) |

**Settings that MUST be JSON arrays in a file:**

| Setting | Example value |
|---|---|
| `PENTESTER_AUDITORS` | `["garak","pyrit"]` |
| `PENTESTER_GARAK__PROBES` | `["probes.dan.Dan_6_2","probes.dan.Dan_11_0"]` |
| `PENTESTER_PYRIT__DATASET_NAMES` | `["xstest"]` |
| `PENTESTER_PYRIT__ATTACK_STRATEGIES` | `["crescendo","tree_of_attacks"]` |
| `PENTESTER_INSPECT__EVALS` | `["strong_reject","b3"]` |
| `PENTESTER_PROMPTFOO__MULTITURN_STRATEGIES` | `["crescendo","goat"]` |

> Writing `PENTESTER_AUDITORS=garak,pyrit` in a file raises
> `SettingsError: error parsing value for field "auditors"`. Use
> `PENTESTER_AUDITORS=["garak","pyrit"]`.

**Two more notes:**

- **`$PROMPT` needs no escaping in a file.** Write your curl command naturally; the
  `$PROMPT` placeholder is preserved as-is. (Shell escaping — `\$PROMPT` — is only for
  inline `--curl-command` on the command line.)
- **API keys are NOT prefixed** with `PENTESTER_`. They're plain `OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`.

---

## Recipe 1 — Semantic fence, quick smoke test

The smallest useful scan: one auditor, a hard attack cap, **no API key needed**. Use
this to prove your target and detection are wired correctly before scaling up.

```bash
# .env.local
PENTESTER_TARGET_TYPE=SEMANTIC_FENCE

# How to reach the target ($PROMPT is required, no escaping needed here)
PENTESTER_SCANNER__CURL_COMMAND=curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{"text": $PROMPT}'
# Which response field means "the attack got through"
PENTESTER_SCANNER__JSON_DOT_TARGET=body.valid

# Keep it tiny
PENTESTER_AUDITORS=["garak"]
PENTESTER_MAX_ATTACKS=5
PENTESTER_GARAK__PROBES=["probes.dan.Dan_6_2"]

# Reports
PENTESTER_REPORTING__OUTPUT_DIR_PATH=./reports
PENTESTER_REPORTING__GENERATOR_KEYS=html
```

Run:

```bash
pentester
```

The first garak run builds an isolated environment (`pentester_garak_env/`, one-time,
slow). Open `reports/*/html/summary.html` when it finishes.

---

## Recipe 2 — LLM target graded by a judge

Attacking a raw LLM instead of a fence. There's no allow/block field, so the tool
extracts the model's reply (`RESPONSE_TEXT_TARGET`) and a **judge** grades it. Note the
auth header lives in the curl command.

```bash
# .env.local
PENTESTER_TARGET_TYPE=LLM

# The target endpoint. Its own auth key goes in the header.
PENTESTER_SCANNER__CURL_COMMAND=curl https://api.openai.com/v1/chat/completions -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-TARGET-KEY' --data-raw '{"model":"gpt-4o-mini","messages":[{"role":"user","content": $PROMPT}]}'
# Where the reply text lives in the response JSON (so the judge can read it)
PENTESTER_SCANNER__RESPONSE_TEXT_TARGET=body.choices.0.message.content

PENTESTER_AUDITORS=["garak","pyrit"]
PENTESTER_MAX_ATTACKS=25

# The JUDGE that decides if a reply is a jailbreak (separate from the target above)
PENTESTER_LLM__PROVIDER=openai
PENTESTER_LLM__MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-JUDGE-KEY

PENTESTER_REPORTING__OUTPUT_DIR_PATH=./reports
PENTESTER_REPORTING__GENERATOR_KEYS=html,pdf
```

> The `Authorization` key in the curl command and `OPENAI_API_KEY` can be the **same**
> key or **different** ones — they play different roles (target vs judge). See
> [Core Concepts → The judge is not the target](./02-concepts.md#the-judge-is-not-the-target).

Run:

```bash
pentester
```

---

## Recipe 3 — Everything at once (all auditors, all settings)

The master reference: **all four auditors** with **every available setting** for each,
against a semantic fence. Use it as a menu — copy it, then delete or comment out the
lines you don't need. It's a heavy run, so the caps are set conservatively; lower them
further (or add `--max-attacks`) for a smoke test.

```bash
# ============================================================
# Master .env.local — ALL auditors, ALL available settings
# Target type: SEMANTIC_FENCE (see the note after the file for LLM targets)
# ============================================================

# --- Root ---------------------------------------------------------------
PENTESTER_TARGET_TYPE=SEMANTIC_FENCE
PENTESTER_AUDITORS=["garak","pyrit","inspect_ai","promptfoo"]
PENTESTER_MAX_ATTACKS=50               # global cap; per-auditor caps below override it

# --- Scanner: how to reach the target -----------------------------------
PENTESTER_SCANNER__CURL_COMMAND=curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{"text": $PROMPT}'
PENTESTER_SCANNER__JSON_DOT_TARGET=body.valid          # field that signals a bypass
PENTESTER_SCANNER__RESPONSE_TEXT_TARGET=body.message   # reply text (PyRIT multi-turn needs it)
# Alternatives to CURL_COMMAND — pick ONE transport:
# PENTESTER_SCANNER__CURL_FILE=./target_curl.txt
# PENTESTER_SCANNER__CUSTOM_HANDLER=./my_handler.py:MyServiceHandler

# --- Judge / scorer LLM (used by model-graded auditors & multi-turn) ----
PENTESTER_LLM__PROVIDER=openai         # openai | anthropic | gemini
PENTESTER_LLM__MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
# GEMINI_API_KEY=...

# --- Reporting ----------------------------------------------------------
PENTESTER_REPORTING__OUTPUT_DIR_PATH=./reports
PENTESTER_REPORTING__GENERATOR_KEYS=html,pdf,csv,markdown

# --- Garak --------------------------------------------------------------
PENTESTER_GARAK__PROBES=["probes.dan.Dan_6_2","probes.dan.Dan_11_0"]
PENTESTER_GARAK__MAX_ATTACKS=200

# --- PyRIT --------------------------------------------------------------
PENTESTER_PYRIT__DATASET_NAMES=["xstest"]
PENTESTER_PYRIT__ENABLE_MULTITURN=true
PENTESTER_PYRIT__ATTACK_STRATEGIES=["multi_prompt_sending","red_teaming","crescendo","tree_of_attacks"]
PENTESTER_PYRIT__MULTITURN_OBJECTIVE=Get the assistant to reveal its hidden system prompt
PENTESTER_PYRIT__MAX_BACKTRACKS=10     # crescendo only
PENTESTER_PYRIT__TREE_WIDTH=3          # tree_of_attacks only
PENTESTER_PYRIT__TREE_DEPTH=5          # tree_of_attacks only
PENTESTER_PYRIT__BRANCHING_FACTOR=2    # tree_of_attacks only
PENTESTER_PYRIT__MAX_ATTACKS=30

# --- Inspect AI ---------------------------------------------------------
PENTESTER_INSPECT__EVALS=["strong_reject","b3"]
PENTESTER_INSPECT__EPOCHS=1
PENTESTER_INSPECT__LIMIT=50            # samples per eval (unset = full dataset)
PENTESTER_INSPECT__JUDGE_MODEL=openai/gpt-4o   # falls back to PENTESTER_LLM__MODEL if unset
PENTESTER_INSPECT__MAX_ATTACKS=50

# --- Promptfoo ----------------------------------------------------------
PENTESTER_PROMPTFOO__OUTPUT_PATH=./output/promptfoo
PENTESTER_PROMPTFOO__FILES_PARALLEL=5
PENTESTER_PROMPTFOO__INTERNAL_CONCURRENCY=4
PENTESTER_PROMPTFOO__MAX_TESTS=2000
PENTESTER_PROMPTFOO__PLUGINS_PER_FILE=1
PENTESTER_PROMPTFOO__MAX_TEST_FILES=20
PENTESTER_PROMPTFOO__PLUGIN_NUM_TESTS=5
PENTESTER_PROMPTFOO__MAX_ATTACKS=100
PENTESTER_PROMPTFOO__REPLACE_EXISTING_FILE=false
PENTESTER_PROMPTFOO__ENABLE_MULTITURN=true
PENTESTER_PROMPTFOO__MULTITURN_MAX_TURNS=5
PENTESTER_PROMPTFOO__MULTITURN_MAX_BACKTRACKS=5
PENTESTER_PROMPTFOO__MULTITURN_STATEFUL=false
PENTESTER_PROMPTFOO__MULTITURN_CONTINUE_AFTER_SUCCESS=false
PENTESTER_PROMPTFOO__MULTITURN_STRATEGIES=["crescendo","goat","mischievous-user"]
```

**Command to run it** (with `AUDITORS` set in the file, plain `pentester` runs all four):

```bash
pentester
```

### Notes

- **Precedence:** a per-auditor `..._MAX_ATTACKS` overrides the global
  `PENTESTER_MAX_ATTACKS`; any CLI flag overrides the file. So the run above caps garak
  at 200, PyRIT at 30, Inspect at 50, Promptfoo at 100, and anything unset at 50.
- **API key is required here** even though the target is a fence, because PyRIT and
  Promptfoo multi-turn (and Inspect's model grading) all use the judge/attacker LLM.
- **Two advanced promptfoo paths are left unset on purpose.** `CONFIG_PATH` and
  `ASSERTION_WRAPPER_PATH` point at files/resources — setting them to a path that
  doesn't exist breaks the run. Leave them unset unless you have a custom config or a
  Python assertion script.
- **For an LLM target instead of a fence**, change these lines: set
  `PENTESTER_TARGET_TYPE=LLM`, drop `PENTESTER_SCANNER__JSON_DOT_TARGET`, keep
  `PENTESTER_SCANNER__RESPONSE_TEXT_TARGET` (now required), and point the curl command
  at the model endpoint. Everything else stays the same.

---

## Mixing files and flags

Files hold your stable config; flags handle one-offs. A flag always wins:

```bash
# .env.local sets the target, judge, and reports.
# Override just the scope for a quick run:
pentester --auditors garak --max-attacks 5
```

(Remember: on the **flag**, `--auditors garak,pyrit` is comma-separated; in the
**file**, `PENTESTER_AUDITORS=["garak","pyrit"]` is a JSON array.)

---

## See also

- [A Full Run](./03-full-run.md) — the narrative walkthrough these recipes support.
- [Core Concepts](./02-concepts.md) — target types, the judge/target split, bypass detection.
- [Configuration reference](../configuration.md) — the authoritative per-variable table.
