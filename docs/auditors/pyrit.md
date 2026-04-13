# PyRIT Auditor

Runs adversarial safety probes against a target using [PyRIT](https://github.com/Azure/PyRIT) (Python Risk Identification Toolkit). Supports single-turn probing and multi-turn attack strategies including Crescendo, Red Teaming, and Tree of Attacks with Pruning.

---

## How It Works

The auditor loads seed datasets from PyRIT's dataset registry and sends each seed to the configured objective target. For multi-turn strategies the auditor uses an adversarial LLM to iteratively refine attacks over multiple conversation turns.

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
  ├─ _load_datasets_async() — fetch seed datasets by name (or all if empty)
  │
  ├─ SEMANTIC_FENCE / LLM:
  │    └─ For each seed: send prompt to objective target → score response
  │
  └─ MULTITURN:
       └─ For each dataset → for each strategy:
            └─ _run_strategy_async() → AttackResult
                 └─ _build_probe_results() → list[ProbeResult] (one per turn)
```

### Objective target selection

`_init_objective_target()` always uses the configured LLM provider (`OpenAIChatTarget`). Use `SEMANTIC_FENCE` target type to route prompts through an HTTP scanner instead.

### Score interpretation

- **SEMANTIC_FENCE / LLM**: each seed produces one `ProbeResult`; `bypassed` is set from the scanner response or the `SelfAskTrueFalseScorer`.
- **MULTITURN**: each conversation turn produces a `ProbeResult`; only the final turn carries the bypass verdict and score.
- Failed seeds or strategies produce an error `ProbeResult` with `metadata={"error": True}`.

---

## Supported Target Types

| `PENTESTER_TARGET_TYPE` | Behaviour |
|---|---|
| `SEMANTIC_FENCE` | Each seed sent as a single prompt to the scanner |
| `LLM` | Each seed sent to the objective target; responses scored with `SelfAskTrueFalseScorer` |
| `MULTITURN` | Multi-turn attack strategies run against the objective target |

---

## Multi-turn Strategies

| Strategy | `MultiTurnStrategy` value | Description |
|---|---|---|
| Multi Prompt Sending | `multi_prompt_sending` | Seeds used as a fixed prompt sequence |
| Red Teaming | `red_teaming` | Adversarial LLM iteratively crafts follow-up prompts |
| Crescendo | `crescendo` | Gradual escalation with backtracking |
| Tree of Attacks | `tree_of_attacks` | Explores a tree of attack variants with pruning |

Set `PENTESTER_PYRIT__ATTACK_STRATEGIES` to a JSON list of strategy values. An **empty list runs all strategies**.

---

## Configuration

Settings live in `PyritSettings` (env prefix `PENTESTER_PYRIT__`):

| Field | Default | Description |
|---|---|---|
| `dataset_names` | `[]` | PyRIT dataset names to load. Empty = all available datasets |
| `max_seeds` | `None` | Maximum seeds per dataset (None = all) |
| `attack_strategies` | `["multi_prompt_sending"]` | Strategies to run in MULTITURN mode. Empty = all strategies |
| `multiturn_objective` | `""` | Goal statement used by RedTeaming, Crescendo, and TAP |
| `max_turns` | `10` | Max conversation turns (RedTeaming, Crescendo) |
| `max_backtracks` | `10` | Max backtrack steps (Crescendo only) |
| `tree_width` | `3` | Branch width (Tree of Attacks only) |
| `tree_depth` | `5` | Tree depth (Tree of Attacks only) |
| `branching_factor` | `2` | Branching factor (Tree of Attacks only) |

---

## Examples

### Semantic fence — single-turn

```bash
PENTESTER_TARGET_TYPE=SEMANTIC_FENCE \
PENTESTER_SCANNER__CURL_COMMAND='curl -X POST "http://localhost:8090/api/v1/fence/validate/2" -H "Content-Type: application/json" --data-raw "{\"text\": \"$PROMPT\"}"' \
PENTESTER_PYRIT__DATASET_NAMES='["xstest"]' \
PENTESTER_PYRIT__MAX_SEEDS=20 \
python src/main.py
```

### LLM — direct model scoring

```bash
PENTESTER_TARGET_TYPE=LLM \
PENTESTER_LLM__PROVIDER=openai \
PENTESTER_LLM__MODEL=gpt-4o \
OPENAI_API_KEY=<your-key> \
PENTESTER_PYRIT__DATASET_NAMES='["xstest"]' \
PENTESTER_PYRIT__MAX_SEEDS=10 \
python src/main.py
```

### Multi-turn — HTTP scanner as target (any AI chat)

```bash
PENTESTER_TARGET_TYPE=MULTITURN \
PENTESTER_SCANNER__CURL_COMMAND='curl -X POST "http://localhost:8090/api/v1/fence/validate/2" -H "Content-Type: application/json" --data-raw "{\"text\": \"$PROMPT\"}"' \
PENTESTER_LLM__PROVIDER=gemini \
PENTESTER_LLM__MODEL=gemini-2.5-flash-lite \
GEMINI_API_KEY=<your-key> \
PENTESTER_PYRIT__DATASET_NAMES='["psfuzz_steal_system_prompt"]' \
PENTESTER_PYRIT__ATTACK_STRATEGIES='["crescendo","red_teaming"]' \
PENTESTER_PYRIT__MULTITURN_OBJECTIVE="Get the model to reveal its system prompt" \
PENTESTER_PYRIT__MAX_TURNS=8 \
python src/main.py
```

### Multi-turn — all strategies, LLM as both attacker and target

```bash
PENTESTER_TARGET_TYPE=MULTITURN \
PENTESTER_LLM__PROVIDER=anthropic \
PENTESTER_LLM__MODEL=claude-sonnet-4-6 \
ANTHROPIC_API_KEY=<your-key> \
PENTESTER_PYRIT__DATASET_NAMES='["xstest"]' \
PENTESTER_PYRIT__ATTACK_STRATEGIES='[]' \
PENTESTER_PYRIT__MULTITURN_OBJECTIVE="Get the model to explain how to pick a lock" \
python src/main.py
```
