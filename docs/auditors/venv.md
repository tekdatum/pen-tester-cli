# Venv Auditor

Wraps any auditor in an isolated Python virtual environment, running it as a subprocess to prevent dependency conflicts with the main project.

---

## How It Works

`VenvAuditor` creates a dedicated venv, installs the wrapped auditor's dependencies into it, and executes the auditor in a subprocess. The target auditor class is never imported in the main process — only its fully-qualified class path is passed as a string.

Constructor arguments (settings, scanner, llm_settings) are serialized with pickle and passed to the subprocess via environment variables. Results are written to a temporary file, deserialized, and returned to the caller as a standard `list[ProbeResult]`.

Package installation is hash-based: a `.packages_hash` file inside the venv tracks the installed set. Reinstalls only happen when the set of packages changes.

### Key components

| Component | Role |
|---|---|
| `VenvAuditor` | Creates the venv, installs dependencies, runs the wrapped auditor in a subprocess |
| `_setup_venv()` | Creates the venv if missing and installs packages if the hash changed |
| `garak-requirements.txt` | Pinned dependencies for the garak venv |

---

## Workflow

```
VenvAuditor.audit()
  │
  ├─ _setup_venv()
  │    ├─ Create venv if path does not exist
  │    └─ pip install if .packages_hash differs
  │
  ├─ Serialize (auditor_kwargs) → base64 pickle → PENTESTER_VENV_PAYLOAD env var
  │
  ├─ subprocess: {venv}/bin/python -c _SCRIPT
  │    ├─ importlib.import_module(auditor_class)
  │    ├─ AuditorClass(**auditor_kwargs).audit()
  │    └─ pickle.dump(results) → PENTESTER_VENV_OUTPUT file
  │
  └─ Deserialize results → list[ProbeResult]
```

---

## Configuration

`VenvAuditor` is constructed directly in `AuditorFactory` — it has no settings class. Parameters:

| Parameter | Description |
|---|---|
| `auditor_class` | Fully-qualified class path, e.g. `"pentester.auditors.garak.GarakAuditor"` |
| `auditor_key` | `AuditorKey` value reported in results |
| `venv_path` | Path where the venv will be created |
| `packages` | Optional list of packages to install |
| `requirements_file` | Optional path to a requirements file (combined with `packages`) |
| `**auditor_kwargs` | Passed through to the wrapped auditor's constructor |

---

## Adding a New Auditor Venv

To wrap a different auditor in its own venv:

1. Create a `<name>-requirements.txt` at the project root with the auditor's pinned dependencies.
2. Register it in `AuditorFactory`:

```python
"my_auditor": lambda: VenvAuditor(
    auditor_class="pentester.auditors.my_auditor.MyAuditor",
    auditor_key=AuditorKey.MY_AUDITOR,
    venv_path="pentester_my_auditor_env",
    requirements_file=str(_PROJECT_ROOT / "my-auditor-requirements.txt"),
    settings=settings.my_auditor,
    scanner=self._scanner,
),
```
