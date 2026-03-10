## Configuration

Settings are managed by `src/pentester/config/settings.py` using [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) v2. Values are loaded from environment variables and optional `.env` files, then validated and exposed as a typed `PentesterSettings` object.

---

### Environment variables

All variables are prefixed with `PENTESTER_`.

| Variable | Type | Default | Description |
|---|---|---|---|
| `PENTESTER_OUTPUT_DIR` | `Path` | `./output` | Directory where output files are written |
| `PENTESTER_TARGET_TYPE` | `TargetType` | `SEMANTIC_FENCE` | Category of the target being scanned |
| `PENTESTER_SCANNER__CURL_COMMAND` | `str \| None` | `None` | curl command string used to target the model |
| `PENTESTER_SCANNER__JSON_DOT_TARGET` | `str \| None` | `None` | dot-notation path to extract value from response |
| `PENTESTER_REPORTING__OUTPUT_DIR_PATH` | `str` | `./output/` | Directory where report files are written |
| `PENTESTER_REPORTING__GENERATOR_KEYS` | `str` | `pdf,csv,html,markdown` | Comma-separated list of report formats to generate |

**`TargetType` values:**

| Value | Description |
|---|---|
| `LLM` | Target is a large language model |
| `SEMANTIC_FENCE` | Target is a semantic fence / prompt guardrail |

---

### `.env` files

Settings are loaded in this order — later sources win:

```
.env          ← shared defaults
.env.local    ← personal overrides
```

Copy `.env.example` to get started:

```bash
cp .env.example .env
```

`.env.example`:

```bash
# Output directory for scan results (default: ./output)
PENTESTER_OUTPUT_DIR=./output

# Target type: LLM | SEMANTIC_FENCE  (default: SEMANTIC_FENCE)
PENTESTER_TARGET_TYPE=SEMANTIC_FENCE
```

Unknown variables are silently ignored, so it is safe to share `.env` files across multiple tools in the same environment.

---

### Usage

**Reading settings anywhere in the package:**

```python
from pentester.config import get_settings

settings = get_settings()
print(settings.output_dir)
print(settings.target_type)
```

`get_settings()` returns a cached singleton — the files and environment are only parsed once per process.

**Using `TargetType` directly:**

```python
from pentester.config import TargetType

if settings.target_type == TargetType.LLM:
    ...
```

Because `TargetType` extends `str`, enum members compare and serialize as plain strings:

```python
settings.target_type == "LLM"  # True
settings.target_type.value     # "LLM"
```

**Overriding at the command line:**

```bash
PENTESTER_OUTPUT_DIR=/tmp/scans PENTESTER_TARGET_TYPE=LLM python sample.py
```

---

### Nested settings (extension pattern)

The `__` delimiter is already configured, so future nested models require no additional setup:

```python
# Future addition — not yet implemented
class ScanSettings(BaseModel):
    timeout: int = 30

class PentesterSettings(BaseSettings):
    scan: ScanSettings = ScanSettings()
```

```bash
# Env var for the nested field:
PENTESTER_SCAN__TIMEOUT=60
```

---

### Example script

`src/configuration_sample.py` demonstrates all key behaviours in a single runnable file.

```python
import os

from pentester.config.settings import TargetType, clear_settings_cache, get_settings

# 1. Default settings
settings = get_settings()
print("=== Default settings ===")
print(f"  output_dir  : {settings.output_dir}")
print(f"  target_type : {settings.target_type}")
print(f"  target_type value: {settings.target_type.value!r}")

# 2. Singleton cache — same object returned on every call
settings2 = get_settings()
print("\n=== Singleton cache ===")
print(f"  get_settings() is get_settings(): {settings is settings2}")

# 3. Env var override — clear cache first so the new values are picked up
os.environ["PENTESTER_OUTPUT_DIR"] = "/tmp/demo-scan"
os.environ["PENTESTER_TARGET_TYPE"] = "LLM"
clear_settings_cache()

overridden = get_settings()
print("\n=== After env var override + cache clear ===")
print(f"  output_dir  : {overridden.output_dir}")
print(f"  target_type : {overridden.target_type}")

# 4. Enumerate all TargetType members
print("\n=== TargetType members ===")
for member in TargetType:
    print(f"  {member.name} = {member.value!r}")

# 5. TargetType is also a plain string
custom = TargetType.LLM
print("\n=== Direct TargetType usage ===")
print(f"  custom type : {custom}  (is str: {isinstance(custom, str)})")
```

**Run it:**

```bash
PYTHONPATH=src python src/configuration_sample.py
```

**Expected output:**

```
=== Default settings ===
  output_dir  : output
  target_type : SEMANTIC_FENCE
  target_type value: 'SEMANTIC_FENCE'

=== Singleton cache ===
  get_settings() is get_settings(): True

=== After env var override + cache clear ===
  output_dir  : /tmp/demo-scan
  target_type : LLM

=== TargetType members ===
  LLM = 'LLM'
  SEMANTIC_FENCE = 'SEMANTIC_FENCE'

=== Direct TargetType usage ===
  custom type : LLM  (is str: True)
```

**Override at the command line:**

```bash
PENTESTER_OUTPUT_DIR=/tmp/scans PENTESTER_TARGET_TYPE=LLM PYTHONPATH=src python src/configuration_sample.py
```
