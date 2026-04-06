# Pentester CLI

Pentester CLI is a command-line tool for running automated prompt-injection security audits against AI systems. It fires a configurable curl command at a target, injects attack prompts, evaluates whether the target was bypassed, and generates reports in multiple formats.

---

## Installation

Install from PyPI:

```
pip install pentester
```

Or install directly from the repository:

```
pip install git+https://github.com/tekdatum/pen-tester-cli.git
```

To include development tools (linter, type checker, test suite):

```
pip install "pentester[dev]"
```

---

## Usage

```
pentester [OPTIONS]
```

All options are optional. Defaults load from environment variables or a `.env` / `.env.local` file. Reports are written to `./output/` by default (override with `--output-dir-path`).

| Option | Description | Default |
|---|---|---|
| `--curl-command` | curl command used to probe the target; must include `$PROMPT` | `None` |
| `--json-dot-target` | Dot-notation path to the response field that indicates bypass (e.g. `body.valid`) | `None` |
| `--output-dir-path` | Directory where report files are written | `./output/` |
| `--generator-keys` | Comma-separated list of report formats: `pdf`, `csv`, `html`, `markdown` | all four |
| `--target-type` | Category of the target: `LLM` or `SEMANTIC_FENCE` | `SEMANTIC_FENCE` |
| `--auditors` | Comma-separated list of auditors to run: `garak`, `pyrit`, `inspect_ai`, `promptfoo` | all |

---

## How To

### 1. Basic usage

Run a scan by providing a curl command pointing at your target:

The tool follows standard curl syntax. The curl command **must** include the `$PROMPT` placeholder, which is replaced with each attack prompt at scan time.

The response can be parsed using dot-notation to extract the field that indicates whether an attack bypassed the target. Both `body.*` and `headers.*` paths are supported.


```
pentester --json-dot-target "body.valid" --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
```

### 2. Specify report formats

Use `--generator-keys` with a comma-separated list of formats:

```
pentester --generator-keys html,pdf --json-dot-target "body.valid" --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
```

### 3. Specify target type

The tool supports LLMs and Semantic Fences (`LLM` | `SEMANTIC_FENCE`). For semantic fences, the tool cannot rely on an auditor's built-in judge, so `--curl-command` and `--json-dot-target` must be provided to fetch and parse the response directly.

```
pentester \
  --target-type LLM \
  --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
```

### 4. Specify auditors

Use `--auditors` with a comma-separated list of auditor names to run only a subset:

```
pentester --auditors garak,pyrit --json-dot-target "body.valid" --curl-command "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
```

### 5. Use the Orchestrator in your own code

You can drive scans programmatically by constructing a `PentesterSettings` object and passing it to `Orchestrator`:

```python
from pentester.config.settings import PentesterSettings
from pentester.enums.target_type import TargetType
from pentester.orchestrator import Orchestrator

settings = PentesterSettings()
settings.target_type = TargetType.SEMANTIC_FENCE
settings.scanner.curl_command = "curl -X POST 'https://api.example.com/chat' -H 'Content-Type: application/json' --data-raw '{\"text\": \"$PROMPT\"}'"
settings.scanner.json_dot_target = "body.valid"
settings.reporting.output_dir_path = "./my-reports"
settings.reporting.generator_keys = "html,pdf"

Orchestrator(settings).execute()
```

---