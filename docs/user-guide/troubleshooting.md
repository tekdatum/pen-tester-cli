# Troubleshooting

Symptom-first. Find the thing that's happening, jump to it, apply the fix. Most
problems come down to one of three things: the tool can't reach your target, it can't
tell whether an attack succeeded, or a dependency (a key, a subprocess) is missing.

**First move for almost any failure:** read the terminal output. The CLI logs progress
and errors to your terminal (stderr). Auditor failures are caught and logged there with
a stack trace, then the run continues — so the log tells you *which* auditor broke and
why.

---

## Install & startup

### `pentester: command not found`

The package installed but its entry-point script isn't on your `PATH`.

- Confirm it installed: `pip show pentester`.
- If you used a virtual environment, make sure it's activated.
- As a fallback, run the module directly: `python -m pentester`.

### `ModuleNotFoundError` on startup

You're likely running from a source checkout without the package installed. Either
`pip install pentester`, or for development install the dependencies from
[Environment setup](../environment.md).

---

## "No scanner configured" / the run refuses to start

```
RuntimeError: No scanner configured. Provide a curl command, curl file, or custom handler.
```

The tool has no way to reach your target. Provide exactly one of:

- `--curl-command "…"` (or `PENTESTER_SCANNER__CURL_COMMAND`)
- `--curl-file ./target.txt` (or `PENTESTER_SCANNER__CURL_FILE`)
- `--custom-handler ./h.py:MyHandler` (or `PENTESTER_SCANNER__CUSTOM_HANDLER`)

If you're targeting a model **directly** (no HTTP), you can instead run with
`--target-type LLM` and set `PENTESTER_LLM__MODEL` — then the auditor calls the model
itself and no scanner is required.

---

## The scanner / curl problems

### The scan errors immediately at "pre-flight"

Before running any auditor, the tool sends a test request to confirm the target is
reachable. A failure here means your curl command or endpoint is the problem — not the
attacks. Run your curl command by hand (replace `$PROMPT` with `"hello"`) and confirm
it returns what you expect.

### `$PROMPT` isn't being substituted / requests look wrong

- **The placeholder is mandatory and literal.** The command must contain `$PROMPT`
  exactly. No placeholder → nothing to inject.
- **Stop your shell from eating it.** In an inline `--curl-command`, escape it as
  `\$PROMPT` so bash doesn't try to expand `$PROMPT` to an empty string before the tool
  ever sees it. (Inside a `.env` file or a `--curl-file`, no escaping is needed.)
- **It's injected as JSON.** `$PROMPT` becomes a JSON-encoded string, so write
  `{"text": $PROMPT}`, **not** `{"text": "$PROMPT"}` — the quotes come from the
  encoding. Double-quoting produces malformed JSON.

### Long or messy curl command

If quoting is fighting you, move the command into a file and use `--curl-file`. Inside
the file you can write it naturally across multiple lines with normal quotes.

---

## Bypass detection problems

### Every attack shows as "not bypassed" (or every one as bypassed)

Your `--json-dot-target` is probably pointing at the wrong field or reading it the wrong
way round.

- Call your endpoint by hand and look at the JSON it returns.
- Set the dotted path to the field whose **truthy value means the attack succeeded**
  (the guard let it through). Prefix with `body.` for the response body or `headers.`
  for a header.
- If your field means the opposite (e.g. `blocked: true` when the request was *safe*),
  there's no invert flag — use a [custom handler](./concepts.md#custom-handlers) where
  you compute `passed` yourself.

### LLM-target run complains about missing reply text

In `--target-type LLM`, the judge needs the model's reply text, extracted via
`PENTESTER_SCANNER__RESPONSE_TEXT_TARGET`. Set it to the dotted path of the text in your
response, e.g. `body.choices.0.message.content` for OpenAI-style APIs. Garak's
LLM-via-scanner mode raises a `ValueError` if it's unset.

---

## Model / API-key problems

### Which key does it even want?

Remember the three roles from [Core Concepts](./concepts.md#the-judge-is-not-the-target):
target, judge, attacker. The `PENTESTER_LLM__*` settings and `OPENAI_API_KEY` /
`ANTHROPIC_API_KEY` / `GEMINI_API_KEY` almost always configure the **judge** or
**attacker**, not your target. Match the key to `PENTESTER_LLM__PROVIDER`:

| `PENTESTER_LLM__PROVIDER` | Required key |
|---|---|
| `openai` | `OPENAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `gemini` | `GEMINI_API_KEY` |

### "It worked for the fence but multi-turn fails without a key"

Expected. **Multi-turn strategies always need an LLM key**, even against a
`SEMANTIC_FENCE` target, because an attacker model drives the conversation. Set the key,
or disable multi-turn (`..._ENABLE_MULTITURN=false`).

---

## Auditor-specific

### First garak run is very slow / hangs on "installing"

garak runs in its own virtual environment (`pentester_garak_env/`), which is **built on
first use**. That one-time build downloads and installs packages and can take several
minutes. Later runs reuse it. If it seems stuck, it's usually pip working — give it
time, and check network access. Details: [Venv isolation](../auditors/venv.md).

### promptfoo fails or hangs

The `promptfoo` auditor shells out to a `promptfoo` CLI (bundled with the pip
dependency) and its red-team generation contacts a remote service. So:

- Ensure the machine has **network access**.
- promptfoo requires a registration **email**; the tool sets a default automatically,
  but a locked-down environment may still block the remote calls.
- Check the terminal log for the exact `promptfoo` command that ran and its exit code —
  you can re-run that command by hand to see promptfoo's own error.

### One auditor's report section is empty

An empty or missing `<auditor>_details` file almost always means **that auditor
errored**, not that zero attacks got through. Auditor failures are isolated: the tool
logs the exception and continues with the others. Scroll the terminal log back to the
`Auditor … failed` line for the cause.

---

## Reports

### No `output/` folder appeared

- If every auditor failed, there may be nothing to report — check the logs.
- Confirm where reports go: `--output-dir-path` / `PENTESTER_REPORTING__OUTPUT_DIR_PATH`
  (default `./output/`). You might be looking in the wrong directory.

### Too many / too few report files

Set the formats explicitly: `--generator-keys html` (one format) up to
`--generator-keys pdf,csv,html,markdown` (all four). Each run also gets its own
timestamped subfolder, so old runs are never overwritten — clean out `output/`
periodically.

---

## Still stuck?

- Re-read [Core Concepts](./concepts.md) — most config mistakes are a target/judge
  mix-up or a target-type mismatch.
- Check the reference docs: [Configuration](../configuration.md),
  [Scanner](../scanner.md), and the per-auditor pages under [`docs/`](../).
- Reproduce with the smallest possible scan (`--auditors garak --max-attacks 1`) to
  isolate whether the problem is your target, your detection, or a specific auditor.
