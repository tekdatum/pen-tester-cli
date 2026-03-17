# InspectAI Auditor

Runs adversarial safety evaluations against a target model or semantic fence using the [inspect_ai](https://inspect.aisi.org.uk/) framework (AISI) with pre-built [inspect_evals](https://github.com/UKGovernmentAISI/inspect_evals) benchmarks.

---

## How It Works

The auditor acts as a bridge between the pen-tester `Scanner` and the `inspect_ai` evaluation framework. Instead of letting `inspect_ai` call an external model provider, all model calls are intercepted and routed through the `Scanner`, which sends the attack prompt to the configured target endpoint.

### Key components

| Component | Role |
|---|---|
| `InspectAIAuditor` | Orchestrates evaluation runs and maps results to `ProbeResult` objects |
| `ScannerModelAPI` | Custom `inspect_ai` model provider — forwards prompts to the `Scanner` |
| `FenceScorerAPI` | Replacement scorer for semantic fence targets — reads `bypassed` from the scanner response |
| `_constants.py` | Eval registry, score keys, default eval lists per target type |

---

## Workflow

```
InspectAIAuditor.audit()
  │
  ├─ Register ScannerModelAPI as a custom model provider ("scanner/default")
  │
  ├─ For each eval (e.g. strong_reject, b3, fortress_adversarial):
  │    │
  │    ├─ Build the Task via _get_task()
  │    │    └─ If target is SEMANTIC_FENCE → replace scorer with FenceScorerAPI
  │    │
  │    ├─ inspect_eval(tasks, model="scanner/default")
  │    │    └─ inspect_ai calls ScannerModelAPI.generate()
  │    │         └─ Scanner.scan(prompt) → TargetResponse
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

Settings live in `InspectSettings` (env prefix `PENTESTER_INSPECT__`):

| Field | Default | Description |
|---|---|---|
| `evals` | `[]` | Eval keys to run. Empty = auto-select by target type |
| `epochs` | `1` | Number of times each sample is evaluated |
| `limit` | `None` | Cap the number of samples per eval (None = full dataset) |
| `judge_model` | `openai/gpt-4o` | Model used to grade `strong_reject` responses |

Example:

```bash
PENTESTER_INSPECT__EVALS='["strong_reject","b3"]'
PENTESTER_INSPECT__EPOCHS=3
PENTESTER_INSPECT__JUDGE_MODEL=openai/gpt-4o-mini
```
