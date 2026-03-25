# InspectAI Auditor

Runs adversarial safety evaluations against a target model or semantic fence using the [inspect_ai](https://inspect.aisi.org.uk/) framework (AISI) with pre-built [inspect_evals](https://github.com/UKGovernmentAISI/inspect_evals) benchmarks.

---

## How It Works

The auditor supports two operating modes depending on configuration:

- **Scanner mode** (default): All model calls are intercepted and routed through the `Scanner`, which sends the attack prompt to the configured target endpoint.
- **Native model mode**: When no `Scanner` is configured but `PENTESTER_LLM__MODEL` is set, the auditor calls the specified Inspect AI model provider (OpenAI, Anthropic, Google) directly.

### Key components

| Component | Role |
|---|---|
| `InspectAIAuditor` | Orchestrates evaluation runs and maps results to `ProbeResult` objects |
| `ScannerModelAPI` | Custom `inspect_ai` model provider — forwards prompts to the `Scanner` (Scanner mode only) |
| `FenceScorerAPI` | Replacement scorer for semantic fence targets — reads `bypassed` from the scanner response (Scanner mode only) |
| `_constants.py` | Eval registry, score keys, default eval lists per target type |
| `_inspect_model_string()` | Builds the Inspect AI model string from `LLMSettings` (e.g. `"google/gemini-flash"`) |

---

## Workflow

```
InspectAIAuditor.audit()
  │
  ├─ Scanner present?
  │    ├─ YES → Register ScannerModelAPI ("scanner/default")
  │    └─ NO  → LLM model set? → get_model("provider/model") [native mode]
  │                               else → warn + return []
  │
  ├─ For each eval (e.g. strong_reject, b3, fortress_adversarial):
  │    │
  │    ├─ Build the Task via _get_task()
  │    │    ├─ Compute effective_judge = judge_model ?? llm.model
  │    │    ├─ Pass effective_judge to each eval that supports a grader
  │    │    └─ If SEMANTIC_FENCE + Scanner mode → replace scorer with FenceScorerAPI
  │    │
  │    ├─ inspect_eval(tasks, model=model)
  │    │
  │    └─ _map_results(EvalLog) → list[ProbeResult]
  │
  └─ Return all ProbeResult objects
```

### Score interpretation

- **Binary evals** (b3, fortress\_adversarial, agentharm, AgentDojo): `CORRECT` → bypassed, `INCORRECT` → blocked.
- **Numeric eval** (strong\_reject, 0–5 scale): normalized to `[0, 1]`; `>= 0.5` is treated as bypassed.
- **Semantic fence**: score comes from `FenceScorerAPI`, which reads the `bypassed` boolean set by the scanner.

---

## Supported Evals

| Eval key | Default for | Score key | Notes |
|---|---|---|---|
| `strong_reject` | LLM + Fence | `strong_reject` | 0–5 numeric, requires `judge_model` |
| `b3` | LLM + Fence | `accuracy` | Fence mode uses only DIO/IIO task types |
| `fortress_adversarial` | LLM + Fence | `accuracy` | |
| `agentharm` | LLM only | `accuracy` | |
| `AgentDojo` | LLM only | `accuracy` | Runs without sandbox tasks |

---

## Configuration

### LLM target model (`PENTESTER_LLM__*`)

Configure the native Inspect AI target model via root `LLMSettings` (env prefix `PENTESTER_LLM__`):

| Field | Default | Description |
|---|---|---|
| `provider` | `openai` | Model provider: `openai`, `anthropic`, or `gemini` |
| `model` | `""` | Model name (without provider prefix, e.g. `gpt-4o-mini`) |

When both `provider` and `model` are set, the auditor uses `"<provider>/<model>"` as the Inspect AI model string. Note: `gemini` maps to `google` in Inspect AI (e.g. `PENTESTER_LLM__MODEL=gemini-flash` → `google/gemini-flash`).

### Inspect auditor settings (`PENTESTER_INSPECT__*`)

Settings live in `InspectSettings` (env prefix `PENTESTER_INSPECT__`):

| Field | Default | Description |
|---|---|---|
| `evals` | `[]` | Eval keys to run. Empty = auto-select by target type |
| `epochs` | `1` | Number of times each sample is evaluated |
| `limit` | `None` | Cap the number of samples per eval (None = full dataset) |
| `judge_model` | `None` | Explicit judge/grader model override. Falls back to `PENTESTER_LLM__MODEL`. When both are absent, each eval uses its own default. |

The effective judge passed to evals is resolved as: `judge_model` → `PENTESTER_LLM__MODEL` → `None` (eval default).

Example — run against OpenAI GPT-4o as both target and judge:

```bash
PENTESTER_LLM__PROVIDER=openai
PENTESTER_LLM__MODEL=gpt-4o

PENTESTER_INSPECT__EVALS='["strong_reject","b3"]'
PENTESTER_INSPECT__EPOCHS=3
```

Example — separate target and judge:

```bash
PENTESTER_LLM__PROVIDER=gemini
PENTESTER_LLM__MODEL=gemini-flash        # target model

PENTESTER_INSPECT__JUDGE_MODEL=openai/gpt-4o  # explicit judge override
```
