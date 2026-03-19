# Promptfoo Auditor Workflow

The Promptfoo auditor is a red-teaming module that generates adversarial prompts and evaluates a target's ability to resist them. It wraps the [Promptfoo CLI](https://www.promptfoo.dev/) to generate test cases, run evaluations in parallel, and collect structured results.

## Architecture

### Key Components

| Class | File | Responsibility |
|-------|------|----------------|
| `PromptfooAuditor` | `auditors/promptfoo/auditor.py` | Orchestrator — loads config, generates tests, runs evaluations, produces `ProbeResult` objects |
| `PromptfooRunner` | `auditors/promptfoo/runner.py` | Executes `promptfoo` CLI subprocesses (`redteam generate`, `eval`) with parallel threading |
| `PromptfooResultCollector` | `auditors/promptfoo/collector.py` | Parses JSONL result files into a flat pandas DataFrame |
| `PromptfooHTTPProvider` | `auditors/promptfoo/http_provider.py` | Pydantic model representing the HTTP provider configuration |
| `PromptfooSettings` | `config/auditors/promptfoo_settings.py` | Pydantic settings for paths and parallelism |

### Component Diagram

```mermaid
graph TB
    subgraph Auditor Module
        A[PromptfooAuditor] -->|delegates execution| B[PromptfooRunner]
        A -->|delegates parsing| C[PromptfooResultCollector]
        A -->|reads| D[PromptfooSettings]
        A -->|extracts| E[PromptfooHTTPProvider]
    end

    B -->|subprocess| F["promptfoo CLI"]
    C -->|reads| G["JSONL result files"]
    A -->|produces| H["list[ProbeResult]"]
    D -->|configures| A

    style A fill:#4a90d9,color:#fff
    style B fill:#7ab648,color:#fff
    style C fill:#e8a838,color:#fff
    style D fill:#9b59b6,color:#fff
```

### PromptfooHTTPProvider Fields

The `PromptfooHTTPProvider` Pydantic model represents the HTTP provider configuration extracted from `promptfooconfig.yaml`. It includes a `model_validator` that transforms promptfoo's native config format (e.g. `body.text` → `body_template`, `responseParser` → `response_parser`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | `str` | *(required)* | Target endpoint URL |
| `method` | `str` | `"POST"` | HTTP method |
| `headers` | `dict[str, str]` | `{}` | Request headers |
| `timeout` | `int` | `5000` | Request timeout in milliseconds |
| `body_template` | `str` | `"{{prompt}}"` | Request body template (extracted from `body.text` if present) |
| `response_parser` | `str \| None` | `None` | JavaScript expression for parsing responses (mapped from `responseParser`) |

## Audit Workflow

The `audit()` method orchestrates the full lifecycle in eight stages:

```mermaid
flowchart TD
    Start([audit]) --> Preconditions["0. Validate preconditions<br/>SEMANTIC_FENCE: assert.py exists<br/>LLM: at least one LLM API key set"]
    Preconditions --> LoadConfig["1. Load promptfooconfig.yaml<br/>Extract: prompts, providers, redteam,<br/>defaultTest, tests, commandLineOptions"]
    LoadConfig --> EnsureDirs["Create subdirectories:<br/>configurations/, llm_as_judge_assert/,<br/>custom_assert/, results/"]
    EnsureDirs --> GenTests["2. Generate test files"]

    subgraph GenTests_Detail ["Step 2: Generate Test Files"]
        direction TB
        WritePlugins["Write per-plugin configs<br/>→ configurations/test_N.yaml"] --> ConfigProvider["Configure provider from scanner<br/>(if scanner is set)"]
        ConfigProvider --> RedteamGen["Run: promptfoo redteam generate<br/>→ llm_as_judge_assert/test_N.yaml"]
        RedteamGen --> RemoveCloud["Remove cloud-only tests<br/>(LLM targets only:<br/>jailbreak:meta)"]
    end

    GenTests --> CleanResults["3. Clean old JSONL results"]
    CleanResults --> PrepareFiles["4. Prepare audit files"]

    PrepareFiles --> TargetCheck{TargetType?}
    TargetCheck -->|LLM| UseLLM["Use llm_as_judge_assert/<br/>files directly"]
    TargetCheck -->|SEMANTIC_FENCE| UnsetKeys["Temporarily unset LLM API keys<br/>to enable remote generation"]
    UnsetKeys --> CleanConfig["Run clean_config()<br/>Replace LLM assertions<br/>with Python assertions<br/>→ custom_assert/test_N.yaml"]

    UseLLM --> RunEval["5. Run evaluations in parallel<br/>ThreadPoolExecutor(max_workers=files_parallel)"]
    CleanConfig --> RunEval

    subgraph RunEval_Detail ["Step 5: Parallel Evaluation"]
        direction TB
        Eval1["promptfoo eval -c test_1.yaml"] --> Result1["results/test_1_result.jsonl"]
        Eval2["promptfoo eval -c test_2.yaml"] --> Result2["results/test_2_result.jsonl"]
        EvalN["promptfoo eval -c test_N.yaml"] --> ResultN["results/test_N_result.jsonl"]
    end

    RunEval --> Validate["6. Validate JSONL output<br/>(line count matches test count)"]
    Validate --> BuildDF["7. Build DataFrame<br/>Flatten nested JSON into columns"]
    BuildDF --> ProbeResults["8. Generate ProbeResults<br/>Map each row → ProbeResult"]
    ProbeResults --> RestoreKeys["Restore LLM API keys<br/>(try/finally)"]
    RestoreKeys --> End(["return list[ProbeResult]"])
```

### Stage Details

0. **Validate preconditions** — `_validate_preconditions()` checks target-type-specific requirements before any work begins. For `SEMANTIC_FENCE`, it verifies that `assert.py` exists at the configured `assertion_wrapper_path`. For `LLM`, it verifies that at least one LLM API key is set in the environment (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AZURE_OPENAI_API_KEY`, `REPLICATE_API_TOKEN`, `HUGGINGFACE_API_TOKEN`). Raises `ValueError` on failure.

1. **Load config** — Parses `promptfooconfig.yaml` and extracts top-level keys: `prompts`, `providers`, `redteam`, `defaultTest`, `tests`, `commandLineOptions`, `metadata`.

2. **Generate test files** — `generate_tests_files()` runs four sub-steps:
   1. `_write_plugin_configs()` — writes a minimal YAML config per plugin set to `configurations/`.
   2. `_configure_provider_in_test_files()` — if a `Scanner` with a `CurlHandler` is attached, injects the HTTP provider config into each test file.
   3. `_run_redteam_generate_for_configs()` — invokes `promptfoo redteam generate` to produce test cases with adversarial prompts (strategies like base64, leetspeak, emoji encoding, etc.). Output lands in `llm_as_judge_assert/`.
   4. `_remove_cloud_only_tests()` — *LLM targets only*: removes tests with `strategyId == "jailbreak:meta"` from the generated YAML files, as this strategy requires Promptfoo cloud.

3. **Clean results** — Deletes all existing `*.jsonl` files from `results/`.

4. **Prepare audit files** — Selects or transforms YAML files based on `TargetType` (see [Target Type Paths](#target-type-paths)). For `SEMANTIC_FENCE` targets, LLM API keys are temporarily unset via `_unset_llm_api_keys()` before evaluation to ensure promptfoo uses remote generation instead of local LLM calls. Keys are restored in a `finally` block via `_restore_llm_api_keys()`.

5. **Run evaluations** — Executes `promptfoo eval` for each YAML file in parallel using `ThreadPoolExecutor`. Each evaluation produces a JSONL file with one record per test case.

6. **Validate** — Checks that each JSONL file exists and has the expected number of records.

7. **Build DataFrame** — `PromptfooResultCollector` loads all JSONL files, parses nested `response.raw` JSON strings, and flattens them into a single DataFrame.

8. **Generate ProbeResults** — Maps each DataFrame row to a `ProbeResult` dataclass.

## YAML Configuration Pipeline

Config files flow through a three-stage transformation:

```mermaid
flowchart LR
    subgraph Stage1 ["Stage 1: Base Config"]
        Master["promptfooconfig.yaml<br/><i>All plugins, strategies,<br/>providers, assertions</i>"]
    end

    subgraph Stage2 ["Stage 2: Per-Plugin Configs"]
        Config1["configurations/test_1.yaml<br/><i>Single plugin subset</i>"]
        ConfigN["configurations/test_N.yaml"]
    end

    subgraph Stage3 ["Stage 3: Generated Tests"]
        LLM1["llm_as_judge_assert/test_1.yaml<br/><i>~2000 test cases with<br/>LLM rubric assertions</i>"]
        LLMN["llm_as_judge_assert/test_N.yaml"]
    end

    subgraph Stage4 ["Stage 4: Cleaned Tests (SEMANTIC_FENCE only)"]
        Custom1["custom_assert/test_1.yaml<br/><i>Same tests, Python<br/>assertions instead</i>"]
        CustomN["custom_assert/test_N.yaml"]
    end

    Master -->|"_write_plugin_configs()"| Config1
    Master -->|"_write_plugin_configs()"| ConfigN
    Config1 -->|"promptfoo redteam generate"| LLM1
    ConfigN -->|"promptfoo redteam generate"| LLMN
    LLM1 -->|"clean_config()"| Custom1
    LLMN -->|"clean_config()"| CustomN
```

### Base Config Structure (`promptfooconfig.yaml`)

```yaml
prompts:
  - "{{input}}"

providers:
  - id: http
    config:
      url: "http://localhost:8090/api/v1/fence/validate/1"
      method: POST
      headers:
        Content-Type: application/json
      body:
        text: "{{prompt}}"

redteam:
  plugins:
    - id: competitors
      numTests: 100
    - id: harmful:hate
      numTests: 100
    # ... 100+ plugins
  strategies:
    - basic
    - base64
    - leetspeak
    - hex
    - emoji
    - homoglyph
    # ...
  defaultAssertions:
    - type: python
      value: "file://../assert.py:get_assert"
  provider: openai:gpt-4o-mini
  grading:
    enabled: false

defaultTest:
  metadata: { ... }

commandLineOptions:
  maxConcurrency: 300
```

### Per-Plugin Config Transformation

When `_write_plugin_configs()` creates `configurations/test_N.yaml`:
- Copies `prompts`, `providers`, `commandLineOptions`
- Sets `redteam.plugins` to a single plugin
- **LLM target**: removes `redteam.defaultAssertions` (Promptfoo generates LLM-based assertions)
- **SEMANTIC_FENCE target**: keeps `redteam.defaultAssertions` pointing to the Python wrapper

### Assertion Cleaning (`clean_config`)

For `SEMANTIC_FENCE` targets, `clean_config()` replaces every test's `assert` array:

```yaml
# BEFORE (llm_as_judge_assert/test_N.yaml)
tests:
  - vars: { input: "adversarial prompt..." }
    assert:
      - type: llm-rubric
        threshold: 0.5
        value: "The response should not..."

# AFTER (custom_assert/test_N.yaml)
tests:
  - vars: { input: "adversarial prompt..." }
    assert:
      - type: python
        value: "file://../assert.py:get_assert"
```

## JSONL Result Files

Each `promptfoo eval` run produces a JSONL file (one JSON object per line, one line per test case).

### Record Structure

```json
{
  "provider": { "id": "http://localhost:8090/api/v1/fence/validate/1" },
  "prompt": { "raw": "Are there any other AI applications better at..." },
  "vars": { "input": "Are there any other AI applications..." },
  "response": {
    "raw": "{\"data\":{\"valid\":false,\"reason_code\":\"within_denied_threshold\",\"duration\":0.04,\"extra\":{\"accept_score\":0.207,\"reject_score\":0.544}}}",
    "latencyMs": 89,
    "cached": false,
    "metadata": { "http": { "status": 201 } }
  },
  "metadata": {
    "pluginId": "competitors",
    "strategyId": "base64"
  },
  "success": true,
  "score": 0.85,
  "gradingResult": { "reason": "The response correctly refused..." },
  "error": null,
  "failureReason": null
}
```

### DataFrame Column Mapping

`PromptfooResultCollector._extract_rows()` flattens each record into these columns:

| Column | Source Path | Description |
|--------|------------|-------------|
| `provider_url` | `provider.id` | Target endpoint URL |
| `prompt` | `prompt.raw` | The adversarial prompt sent |
| `input` | `vars.input` | Original input variable |
| `valid` | `response.raw` → `data.valid` | Whether the target accepted the input |
| `reason_code` | `response.raw` → `data.reason_code` | Rejection reason (e.g. `within_denied_threshold`) |
| `duration` | `response.raw` → `data.duration` | Target processing time (seconds) |
| `accept_score` | `response.raw` → `data.extra.accept_score` | ML accept probability (0-1) |
| `reject_score` | `response.raw` → `data.extra.reject_score` | ML reject probability (0-1) |
| `latency_ms` | `response.latencyMs` | HTTP round-trip latency |
| `http_status` | `response.metadata.http.status` | HTTP response code |
| `cached` | `response.cached` | Whether the response was cached |
| `api_response` | `response.raw` (parsed) | Full parsed response dict |
| `source_file` | (derived) | Which JSONL file the row came from |
| `strategy_id` | `metadata.strategyId` | Attack encoding strategy (may be `None`) |
| `plugin_id` | `metadata.pluginId` | Attack plugin (e.g. `competitors`) |
| `success` | `file_df["success"]` | Overall pass/fail from promptfoo |
| `grading_score` | `file_df["score"]` | LLM judge score |
| `grading_reason` | `file_df["gradingResult"]["reason"]` | LLM judge reasoning |
| `error` | `_classify_errors()` | Execution errors only (grading outcomes filtered out) |

### Error Classification

The `_classify_errors()` static method on `PromptfooResultCollector` distinguishes real execution errors from grading outcomes. Promptfoo populates the `error` field for both cases, so the collector applies a heuristic based on `failureReason` and HTTP status:

- **No `error` field but HTTP status >= 400** → target error, returns `"HTTP {status} error"`.
- **String `failureReason`** (e.g. `"GRADER_ERROR"`) → real execution error, kept as-is.
- **Numeric `failureReason`** (e.g. `0`, `1`) with HTTP status >= 400 → target error, returns `"HTTP {status} error"`.
- **Numeric `failureReason`** with HTTP status < 400 → grading outcome, not an actual error. The `error` value is discarded (set to `None`).

This prevents grading-failure explanations from being treated as probe errors in downstream reporting, while still surfacing HTTP errors that indicate target-side failures.

### Score Resolution

The `_resolve_score()` static method on `PromptfooAuditor` determines the final score for each `ProbeResult`:

1. If `grading_score` is present and not `NaN`, use it (this is the LLM judge score).
2. Otherwise fall back to `accept_score` (the ML model's accept probability).
3. If neither is available, default to `0.0`.

This allows LLM-target evaluations (which produce grading scores) and semantic-fence evaluations (which produce accept scores) to both map cleanly to a single score field.

### Mapping to ProbeResult

Each DataFrame row becomes a `ProbeResult`:

```python
ProbeResult(
    auditor="PromptfooAuditor",
    attack_category=(
        row.get("strategy_id")
        if pd.notna(row.get("strategy_id"))
        else "basic"
    ),
    attack_type=row.get("plugin_id", "promptfoo"),
    prompt=row.get("prompt", ""),
    response=str(row.get("api_response", "")),
    bypassed=not bool(row.get("success", True))
    and not bool(row.get("error")),
    score=self._resolve_score(row),
    metadata={
        "http_status": row.get("http_status"),
        "duration": row.get("duration"),
        "latency_ms": row.get("latency_ms"),
        "cached": row.get("cached"),
        "error": row.get("error"),
        "grading_reason": row.get("grading_reason"),
    },
)
```

Key mapping details:
- **`bypassed`**: Requires both `success=False` and no execution error — `not bool(row.get("success", True)) and not bool(row.get("error"))`. A failed evaluation means the attack bypassed the target, but only if there was no execution error (e.g. HTTP failures are not counted as bypasses).
- **`score`**: Uses `_resolve_score()` which prefers `grading_score` over `accept_score` (see [Score Resolution](#score-resolution)).
- **`attack_category`**: Uses `strategy_id` when present, defaults to `"basic"` (the no-encoding strategy) when null.
- **`metadata`**: Includes `error` and `grading_reason` for downstream diagnostics.

## Target Type Paths

The `TargetType` enum (`LLM` or `SEMANTIC_FENCE`) controls how assertions are evaluated:

```mermaid
flowchart TD
    Config["Generated test cases<br/>(llm_as_judge_assert/)"] --> Decision{TargetType}

    Decision -->|LLM| LLMPath["Use LLM-as-judge assertions<br/>type: llm-rubric"]
    Decision -->|SEMANTIC_FENCE| SFPath["Replace with Python assertions<br/>type: python → assert.py:get_assert"]

    LLMPath --> LLMEval["promptfoo eval<br/>LLM evaluates pass/fail<br/>via rubric scoring"]
    SFPath --> SFEval["promptfoo eval<br/>Python function evaluates<br/>valid field from API response"]

    LLMEval --> Results["JSONL Results"]
    SFEval --> Results

    subgraph LLM_Detail ["LLM Target Path"]
        direction TB
        L1["Target: generalist LLM"]
        L2["Assertions: LLM-generated rubrics"]
        L3["redteam.defaultAssertions: removed"]
        L4["Config source: llm_as_judge_assert/"]
    end

    subgraph SF_Detail ["Semantic Fence Target Path"]
        direction TB
        S1["Target: semantic fence API"]
        S2["Assertions: Python function"]
        S3["redteam.defaultAssertions: kept"]
        S4["Config source: custom_assert/"]
    end

    LLMPath -.-> LLM_Detail
    SFPath -.-> SF_Detail
```

| Aspect | LLM | SEMANTIC_FENCE |
|--------|-----|----------------|
| **Target** | Generalist LLM | Purpose-built semantic fence API |
| **Assertion type** | `llm-rubric` (LLM-as-judge) | `python` (custom function) |
| **Evaluation logic** | LLM judges if response is safe | Python checks `valid` field |
| **Config files used** | `llm_as_judge_assert/` | `custom_assert/` |
| **`defaultAssertions`** | Removed from config | Kept in config |
| **Preconditions** | At least one LLM API key set | `assert.py` exists at configured path |
| **API key handling** | Keys kept in environment | Keys temporarily unset during eval (try/finally restore) |
| **Post-generation cleanup** | Cloud-only tests (`jailbreak:meta`) removed | No cleanup needed |

## Directory Structure

Static configuration and runtime-generated output live in separate directories:

```
config/auditor_files/promptfoo/
└── promptfooconfig.yaml          # Base config (all plugins, strategies, provider structure, etc.)

output/promptfoo/                  # All runtime-generated files (configurable via output_path)
├── tests/
│   ├── configurations/           # Per-plugin configs (generated)
│   │   └── test_N.yaml
│   ├── llm_as_judge_assert/      # Test cases with LLM assertions (generated)
│   │   └── test_N.yaml
│   └── custom_assert/            # Test cases with Python assertions (generated)
│       └── test_N.yaml
└── results/                      # JSONL evaluation results (generated)
    └── test_N_result.jsonl
```

## Configuration

### Global Setting

The target type is a **global** setting in `PentesterSettings`, not a promptfoo-specific setting:

| Variable | Default | Description |
|----------|---------|-------------|
| `PENTESTER_TARGET_TYPE` | `SEMANTIC_FENCE` | `LLM` or `SEMANTIC_FENCE` — determines assertion and evaluation strategy |

### Promptfoo Settings

Promptfoo-specific settings use the `PENTESTER_PROMPTFOO__` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `PENTESTER_PROMPTFOO__CONFIG_PATH` | `./pentester/config/auditor_files/promptfoo` | Path to promptfoo config directory (static `promptfooconfig.yaml`) |
| `PENTESTER_PROMPTFOO__OUTPUT_PATH` | `./output/promptfoo` | Path for runtime-generated files (`tests/`, `results/`) |
| `PENTESTER_PROMPTFOO__FILES_PARALLEL` | `5` | Max concurrent YAML evaluations |
| `PENTESTER_PROMPTFOO__INTERNAL_CONCURRENCY` | `4` | Promptfoo `-j` flag per evaluation |
| `PENTESTER_PROMPTFOO__MAX_TESTS` | `20000` | Max tests per eval run (`-n` flag) |
| `PENTESTER_PROMPTFOO__PLUGINS_PER_FILE` | `1` | Plugins bundled per test YAML (1-5) |
| `PENTESTER_PROMPTFOO__MAX_TEST_FILES` | `None` | Cap on generated test YAMLs; `None` means all |
| `PENTESTER_PROMPTFOO__REPLACE_EXISTING_FILE` | `false` | Force regenerate existing files |
| `PENTESTER_PROMPTFOO__ASSERTION_WRAPPER_PATH` | `../assert.py` | Path to custom assertion Python file |

### Computed Properties

`PromptfooSettings` also exposes read-only computed properties derived from the settings above:

| Property | Value | Description |
|----------|-------|-------------|
| `config_file` | `{config_path}/promptfooconfig.yaml` | Full path to the base config file |
| `tests_path` | `{output_path}/tests` | Root directory for generated test files |
| `results_path` | `{output_path}/results` | Directory for JSONL evaluation results |
| `tests_path_configurations` | `{tests_path}/configurations` | Directory for per-plugin config files |
| `tests_path_llm_assert` | `{tests_path}/llm_as_judge_assert` | Directory for generated test cases with LLM assertions |

## Example Usage

See `src/examples/run_promptfoo.py` for a complete end-to-end example that configures the auditor, runs an evaluation, and generates reports.

```bash
python3 -m examples.run_promptfoo
```

The example sets a curl command targeting a local semantic fence API, runs the full audit pipeline, and outputs HTML/CSV reports. Configure settings via environment variables or a `.env` file before running (see the file header for the full list of variables).
