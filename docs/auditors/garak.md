# Garak Auditor

Runs adversarial safety probes against a target model or semantic fence using the [garak](https://github.com/leondz/garak) red-teaming framework.

---

## How It Works

The auditor loads garak probes and routes each generated prompt to the configured target. Responses are evaluated using each probe's built-in detectors.

### Key components

| Component | Role |
|---|---|
| `GarakAuditor` | Orchestrates probe execution and maps results to `ProbeResult` objects |
| `GarakSettings` | Configuration for probes, generations, and random seed |
| `OpenAIGenerator` / `LiteLLMGenerator` | Garak generator used for LLM targets |

---

## Workflow

```
GarakAuditor.audit()
  │
  ├─ _init_garak() — initialise garak internals
  │
  ├─ _load_probes() — instantiate configured probe classes
  │
  ├─ For each probe → for each prompt:
  │    │
  │    ├─ SEMANTIC_FENCE: Scanner.scan(prompt) → TargetResponse
  │    │    └─ bypassed = TargetResponse.bypassed
  │    │
  │    └─ LLM: generator.generate(conversation) → response text
  │         └─ score = _evaluate(probe, prompt, responses)
  │              └─ bypassed = score > 0.5
  │
  └─ Return all ProbeResult objects
```

### Score interpretation

- **SEMANTIC_FENCE**: `bypassed` is read directly from the scanner response.
- **LLM**: each probe's built-in detectors score the response; scores above `0.5` are treated as bypassed.
- Failed prompts (exceptions) produce an error `ProbeResult` with `metadata={"error": True}`.

---

## Supported Target Types

| `PENTESTER_TARGET_TYPE` | Behaviour |
|---|---|
| `SEMANTIC_FENCE` | Prompts are sent via the configured curl scanner |
| `LLM` | Prompts are sent directly to the configured LLM provider |

---

## Configuration

Settings live in `GarakSettings` (env prefix `PENTESTER_GARAK__`):

| Field | Default | Description |
|---|---|---|
| `probes` | `[]` | Garak probe class paths to run. Empty = all available probes |
| `generations` | `1` | Number of attempts per prompt |
| `seed` | `42` | Random seed for reproducibility |

### Supported LLM providers (`PENTESTER_LLM__PROVIDER`)

| Provider | Generator class | Notes |
|---|---|---|
| `openai` | `OpenAIGenerator` | Requires `OPENAI_API_KEY` |
| `anthropic` | `LiteLLMGenerator` | Requires `ANTHROPIC_API_KEY` |
| `gemini` | `LiteLLMGenerator` | Requires `GEMINI_API_KEY` |

---

## Examples

### Semantic fence

```bash
PENTESTER_TARGET_TYPE=SEMANTIC_FENCE \
PENTESTER_SCANNER__CURL_COMMAND='curl -X POST "http://localhost:8090/api/v1/fence/validate/2" -H "Content-Type: application/json" --data-raw "{\"text\": \"$PROMPT\"}"' \
PENTESTER_GARAK__PROBES='["probes.dan.Dan_6_2", "probes.knownbadsignatures.EICAR"]' \
python src/main.py
```

### LLM — OpenAI

```bash
PENTESTER_TARGET_TYPE=LLM \
PENTESTER_LLM__PROVIDER=openai \
PENTESTER_LLM__MODEL=gpt-4o \
OPENAI_API_KEY=<your-key> \
PENTESTER_GARAK__PROBES='["probes.dan.Dan_6_2"]' \
PENTESTER_GARAK__GENERATIONS=3 \
python src/main.py
```

### LLM — Gemini

```bash
PENTESTER_TARGET_TYPE=LLM \
PENTESTER_LLM__PROVIDER=gemini \
PENTESTER_LLM__MODEL=gemini-2.0-flash-lite \
GEMINI_API_KEY=<your-key> \
python src/main.py
```
