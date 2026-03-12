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
| `PromptfooSettings` | `config/auditors/promptfoo_settings.py` | Pydantic settings for paths, parallelism, and target type |

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

## Audit Workflow

The `audit()` method orchestrates the full lifecycle in five stages:

```mermaid
flowchart TD
    Start([audit]) --> LoadConfig["1. Load promptfooconfig.yaml<br/>Extract: prompts, providers, redteam,<br/>defaultTest, tests, commandLineOptions"]
    LoadConfig --> EnsureDirs["Create subdirectories:<br/>configurations/, llm_as_judge_assert/,<br/>custom_assert/, results/"]
    EnsureDirs --> GenTests["2. Generate test files"]

    subgraph GenTests_Detail ["Step 2: Generate Test Files"]
        direction TB
        WritePlugins["Write per-plugin configs<br/>→ configurations/test_N.yaml"] --> RedteamGen["Run: promptfoo redteam generate<br/>→ llm_as_judge_assert/test_N.yaml"]
    end

    GenTests --> CleanResults["3. Clean old JSONL results"]
    CleanResults --> PrepareFiles["4. Prepare audit files"]

    PrepareFiles --> TargetCheck{TargetType?}
    TargetCheck -->|LLM| UseLLM["Use llm_as_judge_assert/<br/>files directly"]
    TargetCheck -->|SEMANTIC_FENCE| CleanConfig["Run clean_config()<br/>Replace LLM assertions<br/>with Python assertions<br/>→ custom_assert/test_N.yaml"]

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
    ProbeResults --> End(["return list[ProbeResult]"])
```

### Stage Details

1. **Load config** — Parses `promptfooconfig.yaml` and extracts top-level keys: `prompts`, `providers`, `redteam`, `defaultTest`, `tests`, `commandLineOptions`, `metadata`.

2. **Generate test files** — For each plugin set, writes a minimal YAML config to `configurations/`, then invokes `promptfoo redteam generate` to produce test cases with adversarial prompts (using strategies like base64, leetspeak, emoji encoding, etc.). Output lands in `llm_as_judge_assert/`.

3. **Clean results** — Deletes all existing `*.jsonl` files from `results/`.

4. **Prepare audit files** — Selects or transforms YAML files based on `TargetType` (see [Target Type Paths](#target-type-paths)).

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
  }
}
```

### DataFrame Column Mapping

`PromptfooResultCollector._extract_rows()` flattens each record into these columns:

| Column | Source Path | Description |
|--------|------------|-------------|
| `provider_url` | `provider.id` | Target endpoint URL |
| `prompt` | `prompt.raw` | The adversarial prompt sent |
| `input` | `vars.input` | Original input variable |
| `valid` | `response.raw` → `Field that indicates whether the attack was rejected` | Whether the target accepted the input |
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

### Mapping to ProbeResult

Each DataFrame row becomes a `ProbeResult`:

```python
ProbeResult(
    auditor="PromptfooAuditor",
    attack_category=row["strategy_id"],   # e.g. "base64", "leetspeak"
    attack_type=row["plugin_id"],         # e.g. "competitors"
    prompt=row["prompt"],
    response=str(row["api_response"]),
    bypassed=bool(row["valid"]),          # True = attack got through
    score=float(row["accept_score"]),
    metadata={
        "http_status": row["http_status"],
        "duration": row["duration"],
        "latency_ms": row["latency_ms"],
        "cached": row["cached"],
    },
)
```

## Target Type Paths

The `TargetType` enum (`LLM` or `SEMANTIC_FENCE`) controls how assertions are evaluated:

```mermaid
flowchart TD
    Config["Generated test cases<br/>(llm_as_judge_assert/)"] --> Decision{TargetType}

    Decision -->|LLM| LLMPath["Use LLM-as-judge assertions<br/>type: llm-rubric"]
    Decision -->|SEMANTIC_FENCE| SFPath["Replace with Python assertions<br/>type: python → assert.py:get_assert"]

    LLMPath --> LLMEval["promptfoo eval<br/>LLM evaluates pass/fail<br/>via rubric scoring"]
    SFPath --> SFEval["promptfoo eval<br/>Python function evaluates<br/>Field that indicates whether the attack was rejected from API response"]

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
| **Evaluation logic** | LLM judges if response is safe | Python checks `Field that indicates whether the attack was rejected` field |
| **Config files used** | `llm_as_judge_assert/` | `custom_assert/` |
| **`defaultAssertions`** | Removed from config | Kept in config |

## Directory Structure

```
config/auditor_files/promptfoo/
├── promptfooconfig.yaml          # Base config (all plugins, strategies, providers)
├── tests/
│   ├── configurations/           # Per-plugin configs (generated)
│   │   └── test_N.yaml
│   ├── llm_as_judge_assert/      # Test cases with LLM assertions (generated)
│   │   └── test_N.yaml
│   ├── custom_assert/            # Test cases with Python assertions (generated, SEMANTIC_FENCE only)
│   │   └── test_N.yaml
│   └── assert.py                 # Custom Python assertion wrapper
├── results/                      # JSONL evaluation results (generated)
│   └── test_N_result.jsonl
```

## Configuration

Settings are configured via environment variables with the `PENTESTER_PROMPTFOO__` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `PENTESTER_PROMPTFOO__CONFIG_PATH` | `./pentester/config/auditor_files/promptfoo` | Path to promptfoo config directory |
| `PENTESTER_PROMPTFOO__TARGET_TYPE` | `SEMANTIC_FENCE` | `LLM` or `SEMANTIC_FENCE` |
| `PENTESTER_PROMPTFOO__FILES_PARALLEL` | `5` | Max concurrent YAML evaluations |
| `PENTESTER_PROMPTFOO__INTERNAL_CONCURRENCY` | `4` | Promptfoo `-j` flag per evaluation |
| `PENTESTER_PROMPTFOO__REPLACE_EXISTING_FILE` | `false` | Force regenerate existing files |
| `PENTESTER_PROMPTFOO__ASSERTION_WRAPPER_PATH` | `../assert.py` | Path to custom assertion Python file |
