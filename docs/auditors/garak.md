# Garak Auditor

Runs adversarial safety probes against a target model or semantic fence using the [garak](https://github.com/leondz/garak) red-teaming framework.

---

## How It Works

The auditor loads garak probes and routes each generated prompt to the configured target. Responses are evaluated using each probe's built-in detectors.

### Key components

| Component | Role |
|---|---|
| `GarakAuditor` | Orchestrates probe execution and maps results to `ProbeResult` objects |
| `ScannerGenerator` | Garak `Generator` subclass that routes prompts through an HTTP scanner instead of calling an LLM directly |
| `GarakSettings` | Configuration for probes, generations, and random seed |
| `OpenAIGenerator` / `LiteLLMGenerator` | Native Garak generators used when targeting an LLM directly |

---

## Workflow

```
GarakAuditor.audit()
  │
  ├─ _init_garak()     — bootstrap garak internals, disable interactive mode
  │
  ├─ _load_probes()    — instantiate configured probe classes
  │
  ├─ For each probe → for each prompt:
  │    │
  │    ├─ SEMANTIC_FENCE: Scanner.scan(prompt) → TargetResponse
  │    │    └─ bypassed = TargetResponse.bypassed  (scanner decides)
  │    │
  │    └─ LLM: generator.generate(conversation) → response text
  │         │
  │         ├─ generator = ScannerGenerator    (if a Scanner was injected)
  │         │    └─ routes prompt via HTTP, extracts reply with response_text_target
  │         │
  │         └─ generator = OpenAIGenerator / LiteLLMGenerator  (native LLM)
  │
  │         score = _evaluate(probe, prompt, responses)
  │              └─ runs probe's built-in detectors, returns max score
  │         bypassed = not ThresholdEvaluator.test(score)  (threshold default: 0.5)
  │
  └─ Return all ProbeResult objects
```

### Score interpretation

- **SEMANTIC_FENCE**: `bypassed` is read directly from the scanner response; no scoring.
- **LLM**: each probe's built-in detectors score the response on `[0, 1]`. Scores above `ThresholdEvaluator`'s threshold (default `0.5`) are treated as bypassed.
- Failed prompts (exceptions) produce an error `ProbeResult` with `bypassed=False` and `metadata={"error": True}`.

---

## Supported Target Types

| `PENTESTER_TARGET_TYPE` | Generator used | Bypass source |
|---|---|---|
| `SEMANTIC_FENCE` | None — Scanner called directly | `TargetResponse.bypassed` |
| `LLM` (with scanner) | `ScannerGenerator` wrapping the HTTP scanner | Probe detector score |
| `LLM` (no scanner) | `OpenAIGenerator` or `LiteLLMGenerator` | Probe detector score |

The `LLM` + scanner combination is useful when the LLM sits behind an HTTP proxy and you want Garak's detector-based scoring rather than the fence's own bypass signal.

---

## Configuration

Settings live in `GarakSettings` (env prefix `PENTESTER_GARAK__`):

| Field | Default | Description |
|---|---|---|
| `probes` | `[]` | Garak probe specs to run. Empty = all active probes. Accepts module paths (`probes.dan`) or full class paths (`probes.dan.Dan_6_2`) |
| `generations` | `1` | Number of attempts per prompt |
| `seed` | `42` | Random seed for reproducibility |

### Supported LLM providers (`PENTESTER_LLM__PROVIDER`)

| Provider | Generator class | Notes |
|---|---|---|
| `openai` | `OpenAIGenerator` (reasoning models) or `OpenAIGenerator` | Requires `OPENAI_API_KEY`. Models starting with `o` use `OpenAIReasoningGenerator` |
| `anthropic` | `LiteLLMGenerator` | Requires `ANTHROPIC_API_KEY`. `top_p` is forced to `None` (not supported by Anthropic) |
| `gemini` | `LiteLLMGenerator` | Requires `GEMINI_API_KEY` |
| `deepseek` | `OpenAICompatible` | Requires `DEEPSEEK_API_KEY`. Points at `https://api.deepseek.com/v1`; garak's default `#`/`;` stop sequences are suppressed so replies are not truncated. Runs with DeepSeek's default thinking mode; to turn it off, use a curl command or custom handler that sends `"thinking": {"type": "disabled"}` |

### LLM-as-judge detectors (`detectors.judge.*`)

Most garak detectors are rule-based or local classifiers, so they score replies the same way whatever the target is. A few are LLM-as-judge detectors, which default to an NVIDIA NIM model and need `NIM_API_KEY`.

Set `PENTESTER_GARAK__JUDGE_MODEL` to `<provider>/<model>` to use another judge, e.g. `deepseek/deepseek-chat` or `openai/gpt-4o-mini`. The provider is one of `openai`, `anthropic`, `gemini` or `deepseek`, reached through its OpenAI-compatible endpoint with its usual API key (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`). Unset, garak's default judge is kept. The setting is independent of `PENTESTER_LLM__*`, so pick a model other than the target's if you want an independent check.

No probe that this auditor runs uses these detectors today: the only one, `fitd`, is inactive by default and builds its prompts at runtime, which this auditor doesn't run. The setting is for custom or future probes.

### Scanner response extraction (`PENTESTER_SCANNER__RESPONSE_TEXT_TARGET`)

When using `ScannerGenerator` (LLM mode with a scanner injected), this dot-path locates the model's reply text inside the HTTP response JSON body. **Required** — if not set, `ScannerGenerator` will raise a `ValueError` at runtime.

Example for OpenAI-compatible endpoints: `body.choices.0.message.content`

---

## Examples

### Semantic fence

```bash
PENTESTER_TARGET_TYPE=SEMANTIC_FENCE \
PENTESTER_SCANNER__CURL_COMMAND='curl -X POST "http://localhost:8090/api/v1/fence/validate/2" -H "Content-Type: application/json" --data-raw "{\"text\": $PROMPT}"' \
PENTESTER_GARAK__PROBES='["probes.dan.Dan_6_2", "probes.knownbadsignatures.EICAR"]' \
python src/main.py
```

### LLM — OpenAI (direct)

```bash
PENTESTER_TARGET_TYPE=LLM \
PENTESTER_LLM__PROVIDER=openai \
PENTESTER_LLM__MODEL=gpt-4o \
OPENAI_API_KEY=<your-key> \
PENTESTER_GARAK__PROBES='["probes.dan.Dan_6_2"]' \
PENTESTER_GARAK__GENERATIONS=3 \
python src/main.py
```

### LLM — via HTTP proxy (ScannerGenerator)

```bash
PENTESTER_TARGET_TYPE=LLM \
PENTESTER_SCANNER__CURL_COMMAND='curl -X POST "http://localhost:8080/v1/chat/completions" -H "Content-Type: application/json" --data-raw "{\"messages\": [{\"role\": \"user\", \"content\": $PROMPT}]}"' \
PENTESTER_SCANNER__RESPONSE_TEXT_TARGET=body.choices.0.message.content \
PENTESTER_GARAK__PROBES='["probes.dan.Dan_6_2"]' \
python src/main.py
```

### LLM — DeepSeek

```bash
PENTESTER_TARGET_TYPE=LLM \
PENTESTER_LLM__PROVIDER=deepseek \
PENTESTER_LLM__MODEL=deepseek-chat \
DEEPSEEK_API_KEY=<your-key> \
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
