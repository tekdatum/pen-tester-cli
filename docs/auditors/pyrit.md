# PyRIT Auditor

Runs adversarial safety probes against a target using [PyRIT](https://github.com/Azure/PyRIT) (Python Risk Identification Toolkit). Supports single-turn probing and optional multi-turn attack strategies including Crescendo, Red Teaming, and Tree of Attacks with Pruning.

---

## How It Works

The auditor loads seed datasets from PyRIT's dataset registry and sends each seed to the configured objective target. When `enable_multiturn` is `True`, multi-turn attack strategies run after the single-turn phase and their results are combined into the same report.

### Key components

| Component | Role |
|---|---|
| `PyritAuditor` | Orchestrates dataset loading, strategy execution, and result mapping |
| `PyritSettings` | Configuration for datasets, strategies, and per-strategy tuning |

---

## Workflow

```
PyritAuditor.audit()
  │
  ├─ initialize_pyrit_async() — set up in-memory PyRIT database
  │
  ├─ _audit_async()
  │    │
  │    ├─ _load_datasets_async() — fetch seed datasets (all if dataset_names is empty)
  │    │
  │    ├─ Single-turn phase (always runs):
  │    │    └─ For each seed:
  │    │         ├─ SEMANTIC_FENCE: Scanner.scan(prompt) → bypassed from response
  │    │         └─ LLM: target.send_prompt_async() → SelfAskTrueFalseScorer → bypassed
  │    │
  │    └─ Multi-turn phase (enable_multiturn=True):
  │         └─ _audit_multiturn_async()
  │              └─ For each dataset → for each strategy:
  │                   └─ _run_strategy_async() → AttackResult
  │                        └─ _build_probe_results() → list[ProbeResult] (one per turn)
  │
  └─ Return combined single-turn + multi-turn ProbeResults
```

### Objective target selection

`_init_objective_target()` always uses the configured LLM provider (`OpenAIChatTarget`). Use `SEMANTIC_FENCE` target type to route prompts through an HTTP scanner instead.

### Score interpretation

- **SEMANTIC_FENCE (single-turn)**: `bypassed` is read directly from the scanner response; no scorer involved.
- **LLM (single-turn)**: `SelfAskTrueFalseScorer` evaluates the response; `bypassed=True` if the scorer returns True.
- **Multi-turn**: each conversation turn produces one `ProbeResult`. Only the **final turn** carries the bypass verdict and score; all earlier turns have `bypassed=False` and `score=None`.
- `attack_type` is `"default"` for single-turn results and the strategy name (e.g. `"crescendo"`) for multi-turn results.
- Failed seeds or strategies produce an error `ProbeResult` with `bypassed=False` and `metadata={"error": True}`.

---

## Supported Target Types

| `PENTESTER_TARGET_TYPE` | Single-turn behaviour | Multi-turn (enable_multiturn=True) |
|---|---|---|
| `SEMANTIC_FENCE` | Each seed sent once to the scanner | Strategies run against `ScannerTarget` |
| `LLM` | Each seed sent to `OpenAIChatTarget`; scored with `SelfAskTrueFalseScorer` | Strategies run against `OpenAIChatTarget` |

**`SEMANTIC_FENCE` multi-turn requires `PENTESTER_SCANNER__RESPONSE_TEXT_TARGET`.**
`ScannerTarget` stores each assistant turn in PyRIT's conversation memory so the attacker LLM can reason about prior responses. The stored value must be plain text — if `response_text_target` is not set, `ScannerTarget` raises a `ValueError` at runtime. Example: `body.choices.0.message.content`.

---

## Multi-turn Strategies

| Strategy | `MultiTurnStrategy` value | Description |
|---|---|---|
| Multi Prompt Sending | `multi_prompt_sending` | Seeds used as a fixed prompt sequence; no adversarial LLM |
| Red Teaming | `red_teaming` | Adversarial LLM iteratively crafts follow-up prompts up to `max_turns` |
| Crescendo | `crescendo` | Gradual escalation with backtracking; controlled by `max_turns` and `max_backtracks` |
| Tree of Attacks | `tree_of_attacks` | Explores a tree of attack variants with pruning; controlled by `tree_width`, `tree_depth`, `branching_factor` |

Set `PENTESTER_PYRIT__ATTACK_STRATEGIES` to a JSON list of strategy values. An **empty list runs all strategies**.

---

## Configuration

Settings live in `PyritSettings` (env prefix `PENTESTER_PYRIT__`):

| Field | Default | Description |
|---|---|---|
| `dataset_names` | `[]` | PyRIT dataset names to load. Empty = all available datasets |
| `max_seeds` | `None` | Maximum seeds per dataset (None = all) |
| `enable_multiturn` | `True` | Whether to run multi-turn attack strategies after single-turn probes |
| `attack_strategies` | `["multi_prompt_sending"]` | Strategies to run in the multi-turn phase. Empty = all strategies |
| `multiturn_objective` | `""` | Goal statement used by RedTeaming, Crescendo, and TAP |
| `max_turns` | `10` | Max conversation turns (RedTeaming, Crescendo) |
| `max_backtracks` | `10` | Max backtrack steps (Crescendo only) |
| `tree_width` | `3` | Branch width (Tree of Attacks only) |
| `tree_depth` | `5` | Tree depth (Tree of Attacks only) |
| `branching_factor` | `2` | Branching factor (Tree of Attacks only) |

---

## Examples

### Semantic fence — single-turn only

```bash
PENTESTER_TARGET_TYPE=SEMANTIC_FENCE \
PENTESTER_SCANNER__CURL_COMMAND='curl -X POST "http://localhost:8090/api/v1/fence/validate/2" -H "Content-Type: application/json" --data-raw "{\"text\": $PROMPT}"' \
PENTESTER_PYRIT__DATASET_NAMES='["xstest"]' \
PENTESTER_PYRIT__MAX_SEEDS=20 \
PENTESTER_PYRIT__ENABLE_MULTITURN=false \
python src/main.py
```

### Semantic fence — single-turn + multi-turn

```bash
PENTESTER_TARGET_TYPE=SEMANTIC_FENCE \
PENTESTER_SCANNER__CURL_COMMAND='curl -X POST "http://localhost:8090/api/v1/fence/validate/2" -H "Content-Type: application/json" --data-raw "{\"text\": $PROMPT}"' \
PENTESTER_SCANNER__RESPONSE_TEXT_TARGET=body.choices.0.message.content \
PENTESTER_LLM__PROVIDER=gemini \
PENTESTER_LLM__MODEL=gemini-2.5-flash-lite \
GEMINI_API_KEY=<your-key> \
PENTESTER_PYRIT__DATASET_NAMES='["psfuzz_steal_system_prompt"]' \
PENTESTER_PYRIT__ATTACK_STRATEGIES='["crescendo","red_teaming"]' \
PENTESTER_PYRIT__MULTITURN_OBJECTIVE="Get the model to reveal its system prompt" \
PENTESTER_PYRIT__MAX_TURNS=8 \
python src/main.py
```

### LLM — direct model, single-turn only

```bash
PENTESTER_TARGET_TYPE=LLM \
PENTESTER_LLM__PROVIDER=openai \
PENTESTER_LLM__MODEL=gpt-4o \
OPENAI_API_KEY=<your-key> \
PENTESTER_PYRIT__DATASET_NAMES='["xstest"]' \
PENTESTER_PYRIT__MAX_SEEDS=10 \
PENTESTER_PYRIT__ENABLE_MULTITURN=false \
python src/main.py
```

### LLM — all strategies, LLM as both attacker and target

```bash
PENTESTER_TARGET_TYPE=LLM \
PENTESTER_LLM__PROVIDER=anthropic \
PENTESTER_LLM__MODEL=claude-sonnet-4-6 \
ANTHROPIC_API_KEY=<your-key> \
PENTESTER_PYRIT__DATASET_NAMES='["xstest"]' \
PENTESTER_PYRIT__ATTACK_STRATEGIES='[]' \
PENTESTER_PYRIT__MULTITURN_OBJECTIVE="Get the model to explain how to pick a lock" \
python src/main.py
```
