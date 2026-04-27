# Pentester CLI

Pentester CLI is a security auditing library that runs automated adversarial attacks against AI systems — LLMs and semantic fences alike. It coordinates multiple red-teaming frameworks, routes attack prompts to your target via HTTP or a custom handler, and produces reports in PDF, HTML, CSV, and Markdown.

---

## Installation

Install from PyPI:

```bash
pip install pentester
```

Or install directly from the repository:

```bash
pip install git+https://github.com/tekdatum/pen-tester-cli.git
```

To include development tools (linter, type checker, test suite):

```bash
pip install "pentester[dev]"
```

---

## Auditors

Four red-teaming frameworks are available. Each maps to a short key used in `--auditors` and env vars.

| Key | Framework | What it tests |
|---|---|---|
| `garak` | [garak](https://github.com/leondz/garak) | 50+ probe categories: DAN jailbreaks, known-bad signatures, prompt injections, encoding attacks |
| `pyrit` | [PyRIT](https://github.com/Azure/PyRIT) (Microsoft) | Single-turn seeds + multi-turn strategies: Crescendo, Red Teaming, Tree of Attacks with Pruning |
| `inspect_ai` | [inspect_ai](https://inspect.aisi.org.uk/) (AISI) | StrongREJECT, B3, Fortress, AgentHarm, AgentDojo benchmarks |
| `promptfoo` | [promptfoo](https://promptfoo.dev/) | Config-driven red team probing |

---

## Usage

```
pentester [OPTIONS]
```

All options are optional. Defaults load from environment variables or a `.env` / `.env.local` file. Reports are written to `./output/` by default.

| Option | Description | Default |
|---|---|---|
| `--custom-handler` | Custom request handler in format `path/to/file.py:ClassName` | `None` |
| `--curl-command` | curl command used to probe the target; must include `$PROMPT` | `None` |
| `--curl-file` | Path to a file containing the curl command (alternative to `--curl-command`) | `None` |
| `--json-dot-target` | Dot-notation path to the response field that indicates bypass (e.g. `body.valid`) | `None` |
| `--output-dir-path` | Directory where report files are written | `./output/` |
| `--generator-keys` | Comma-separated list of report formats: `pdf`, `csv`, `html`, `markdown` | all four |
| `--target-type` | Category of the target: `LLM` or `SEMANTIC_FENCE` | `SEMANTIC_FENCE` |
| `--auditors` | Comma-separated list of auditors to run: `garak`, `pyrit`, `inspect_ai`, `promptfoo` | all |
| `--max-attacks` | Cap the number of attack prompts per auditor | `None` |

---

## How To

### 1. Use a custom handler (Python SDK, gRPC, local model)

If your target is not accessible via HTTP, implement a `CustomHandler`. This is the most flexible integration option.

```python
# my_handler.py
from pentester import CustomHandler, HandlerResponse

class MyServiceHandler(CustomHandler):
    def request(self, text: str) -> HandlerResponse:
        response = my_client.send(text)
        return HandlerResponse(
            response=response.raw_text,
            passed=response.was_blocked,  # True = bypassed, False = blocked
        )
```

Pass it to the CLI with `--custom-handler <path>:<ClassName>`:

```bash
pentester --custom-handler ./my_handler.py:MyServiceHandler --auditors garak,pyrit
```

### 2. Basic usage with curl

Run a scan by providing a curl command pointing at your target.

The curl command **must** include the `$PROMPT` placeholder, which is replaced with each attack prompt at scan time. Use `--json-dot-target` to extract the field from the JSON response that indicates whether the attack bypassed the target (`body.*` and `headers.*` paths are supported).

```bash
pentester \
  --json-dot-target "body.valid" \
  --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
```

### 3. Load the curl command from a file

If the curl command is long or contains special characters, store it in a file and pass the path with `--curl-file`:

```bash
# curl_command.txt
curl -X POST 'https://api.example.com/chat' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer TOKEN' \
  --data-raw '{"text": "$PROMPT"}'
```

```bash
pentester --curl-file ./curl_command.txt --json-dot-target "body.valid"
```

### 4. Specify report formats

Use `--generator-keys` with a comma-separated list of formats. Use `--output-dir-path` to change the output directory (default: `./output/`):

```bash
pentester \
  --generator-keys html,pdf \
  --output-dir-path ./reports \
  --json-dot-target "body.valid" \
  --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
```

### 5. Specify auditors

Use `--auditors` with a comma-separated list to run only a subset:

```bash
pentester \
  --auditors garak,pyrit \
  --json-dot-target "body.valid" \
  --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
```

### 6. Limit the number of attacks

Use `PENTESTER_MAX_ATTACKS` to cap the number of attack prompts each auditor will run. Useful for quick smoke tests or cost control.

```bash
PENTESTER_MAX_ATTACKS=50 pentester \
  --json-dot-target "body.valid" \
  --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
```

Per-auditor limits take priority over the global cap:

```
PENTESTER_MAX_ATTACKS=50
PENTESTER_GARAK__MAX_ATTACKS=200
```

Here Garak runs up to 200 attacks while every other auditor is capped at 50.

See the full list of per-auditor attack cap variables in [Environment Variables](#environment-variables).

---

## Target Types

| `--target-type` | What it means |
|---|---|
| `SEMANTIC_FENCE` (default) | The target returns a structured response with a field indicating whether the prompt was blocked. Bypass is read directly from that field (e.g. via `--json-dot-target`). |
| `LLM` | The target is a language model. The auditor sends the prompt and uses a judge model (or built-in detectors) to decide if the response is a bypass. |

Use `--target-type LLM` when targeting a language model directly. In this mode the auditor sends prompts and evaluates responses with a judge model — no `--json-dot-target` needed. Requires [LLM keys](#llm-keys).

```bash
pentester \
  --target-type LLM \
  --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
```

Can also be set via environment variable — see [Environment Variables](#environment-variables).

---

## LLM Keys

Some auditors need an LLM to judge whether a target's response constitutes a bypass. The target itself is always reached via curl or a custom handler — the LLM is only the scorer/judge.

Configure the judge via `PENTESTER_LLM__*` env vars:

```bash
PENTESTER_LLM__PROVIDER=openai   # openai | anthropic | gemini
PENTESTER_LLM__MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-...
```

| Provider | Env var |
|---|---|
| `openai` | `OPENAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `gemini` | `GEMINI_API_KEY` |

---

## Reports

Reports are written to `./output/` by default (override with `--output-dir-path`). Use `--generator-keys` to select which formats to generate.

| Format | Key | Contents |
|---|---|---|
| HTML | `html` | Attack summary and per-probe detail table |
| PDF | `pdf` | Attack summary and per-probe detail table, formatted for print or sharing |
| CSV | `csv` | Attack summary and per-probe detail table, suitable for further analysis or filtering |
| Markdown | `markdown` | Attack summary and per-probe detail table, rendered as `.md` |

---

## Programmatic Usage

Drive scans programmatically by constructing a `PentesterSettings` object and passing it to `Orchestrator`:

```python
from pentester.config.settings import PentesterSettings
from pentester.enums.target_type import TargetType
from pentester.orchestrator import Orchestrator

settings = PentesterSettings(
    target_type=TargetType.SEMANTIC_FENCE,
)
settings.scanner.curl_command = "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
settings.scanner.json_dot_target = "body.valid"
settings.reporting.output_dir_path = "./my-reports"
settings.reporting.generator_keys = "html,pdf"

Orchestrator(settings).execute()
```

---

## Environment Variables

All variables use the `PENTESTER_` prefix. Nested settings use double-underscore as delimiter (e.g. `PENTESTER_SCANNER__CURL_COMMAND`). Variables can be passed inline or stored in a `.env` / `.env.local` file at the project root:

```bash
# inline
PENTESTER_TARGET_TYPE=LLM PENTESTER_LLM__MODEL=gpt-4o-mini OPENAI_API_KEY=sk-... pentester --auditors pyrit
```

```bash
# .env file
PENTESTER_TARGET_TYPE=LLM
PENTESTER_LLM__MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-...
```

### Root

| Variable | Default | Description |
|---|---|---|
| `PENTESTER_TARGET_TYPE` | `SEMANTIC_FENCE` | Category of the target: `LLM` or `SEMANTIC_FENCE` |
| `PENTESTER_AUDITORS` | `[]` (all) | Comma-separated list of auditors to run (e.g. `garak,pyrit`) |
| `PENTESTER_MAX_ATTACKS` | `None` | Global attack cap applied to all auditors. Per-auditor settings take priority when set. |

### Scanner

| Variable | Default | Description |
|---|---|---|
| `PENTESTER_SCANNER__CURL_COMMAND` | `None` | curl command string used to probe the target. Must include `"$PROMPT"`. |
| `PENTESTER_SCANNER__CURL_FILE` | `None` | Path to a file containing the curl command (alternative to `CURL_COMMAND`) |
| `PENTESTER_SCANNER__JSON_DOT_TARGET` | `None` | Dot-notation path to the response field that indicates bypass (e.g. `body.valid`) |
| `PENTESTER_SCANNER__RESPONSE_TEXT_TARGET` | `None` | Dot-notation path to extract the LLM reply text from the response body. Required for Garak LLM mode and PyRIT multi-turn (e.g. `body.choices.0.message.content`) |
| `PENTESTER_SCANNER__CUSTOM_HANDLER` | `None` | Custom handler in format `path/to/file.py:ClassName` |

### Reporting

| Variable | Default | Description |
|---|---|---|
| `PENTESTER_REPORTING__OUTPUT_DIR_PATH` | `./output/` | Directory where report files are written |
| `PENTESTER_REPORTING__GENERATOR_KEYS` | `html,markdown,csv,pdf` | Comma-separated list of report formats to generate |

### LLM judge

| Variable | Default | Description |
|---|---|---|
| `PENTESTER_LLM__PROVIDER` | `openai` | LLM provider for the judge: `openai`, `anthropic`, or `gemini` |
| `PENTESTER_LLM__MODEL` | `""` | Model name without provider prefix (e.g. `gpt-4o-mini`) |
| `OPENAI_API_KEY` | — | Required when `PENTESTER_LLM__PROVIDER=openai` |
| `ANTHROPIC_API_KEY` | — | Required when `PENTESTER_LLM__PROVIDER=anthropic` |
| `GEMINI_API_KEY` | — | Required when `PENTESTER_LLM__PROVIDER=gemini` |

### Garak

| Variable | Default | Description |
|---|---|---|
| `PENTESTER_GARAK__PROBES` | `[]` (all) | JSON array of probe specs to run (e.g. `["probes.dan.Dan_6_2"]`) |
| `PENTESTER_GARAK__MAX_ATTACKS` | `None` | Attack cap for Garak. Overrides `PENTESTER_MAX_ATTACKS`. |

### PyRIT

| Variable | Default | Description |
|---|---|---|
| `PENTESTER_PYRIT__DATASET_NAMES` | `[]` (all) | JSON array of dataset names to load (e.g. `["xstest"]`) |
| `PENTESTER_PYRIT__ENABLE_MULTITURN` | `true` | Whether to run multi-turn attack strategies |
| `PENTESTER_PYRIT__ATTACK_STRATEGIES` | `["multi_prompt_sending"]` | JSON array of strategies: `multi_prompt_sending`, `red_teaming`, `crescendo`, `tree_of_attacks` |
| `PENTESTER_PYRIT__MULTITURN_OBJECTIVE` | `""` | Goal statement used by RedTeaming, Crescendo, and Tree of Attacks |
| `PENTESTER_PYRIT__MAX_BACKTRACKS` | `10` | Max backtrack steps (Crescendo only) |
| `PENTESTER_PYRIT__TREE_WIDTH` | `3` | Branch width (Tree of Attacks only) |
| `PENTESTER_PYRIT__TREE_DEPTH` | `5` | Tree depth (Tree of Attacks only) |
| `PENTESTER_PYRIT__BRANCHING_FACTOR` | `2` | Branching factor (Tree of Attacks only) |
| `PENTESTER_PYRIT__MAX_ATTACKS` | `None` | Attack cap for PyRIT. Overrides `PENTESTER_MAX_ATTACKS`. |

### Inspect AI

| Variable | Default | Description |
|---|---|---|
| `PENTESTER_INSPECT__EVALS` | `[]` (auto) | JSON array of eval keys to run (e.g. `["strong_reject","b3"]`). Empty = auto-select by target type. |
| `PENTESTER_INSPECT__EPOCHS` | `1` | Number of times each sample is evaluated |
| `PENTESTER_INSPECT__LIMIT` | `None` | Cap the number of samples per eval |
| `PENTESTER_INSPECT__JUDGE_MODEL` | `None` | Explicit judge model override (e.g. `openai/gpt-4o`). Falls back to `PENTESTER_LLM__MODEL`. |
| `PENTESTER_INSPECT__MAX_ATTACKS` | `None` | Attack cap for Inspect AI. Overrides `PENTESTER_MAX_ATTACKS`. |

### Promptfoo

| Variable | Default | Description |
|---|---|---|
| `PENTESTER_PROMPTFOO__MAX_ATTACKS` | `None` | Attack cap for Promptfoo. Overrides `PENTESTER_MAX_ATTACKS`. |
| `PENTESTER_PROMPTFOO__PLUGIN_NUM_TESTS` | `None` | Override `numTests` on every plugin in generated config files |
| `PENTESTER_PROMPTFOO__ENABLE_MULTITURN` | `false` | Enable multi-turn attack strategies |
| `PENTESTER_PROMPTFOO__MULTITURN_MAX_TURNS` | `5` | Max conversation turns (1–20) |
| `PENTESTER_PROMPTFOO__MULTITURN_MAX_BACKTRACKS` | `5` | Max backtracks for Crescendo (1–20) |
| `PENTESTER_PROMPTFOO__MULTITURN_STATEFUL` | `false` | Whether the target maintains session state. When `false`, full conversation history is sent each turn. |
| `PENTESTER_PROMPTFOO__MULTITURN_STRATEGIES` | all | JSON array of strategies: `crescendo`, `goat`, `jailbreak:hydra`, `mischievous-user` |