# Claude Code Instructions

## Testing

Every change must have full test coverage. For any file created or modified, write corresponding tests before considering the task complete. Run `/validate` after all changes (code + tests) are in place.

---

## Project Structure

```
src/pentester/
├── auditors/               # Auditor implementations
│   ├── auditor_factory.py  # Creates and wires auditor instances
│   ├── models/             # Shared data models (ProbeResult, BaseAuditor)
│   └── <name>.py           # One file per concrete auditor (e.g. garak.py)
├── config/
│   ├── settings.py         # Root PentesterSettings + get_settings() singleton
│   ├── scanner.py          # ScannerSettings
│   └── auditors/           # Per-auditor settings (GarakSettings, etc.)
├── scanners/
│   ├── scanner.py          # Scanner class with from_curl / from_settings
│   ├── models/             # TargetResponse dataclass
│   ├── request_handlers/   # RequestHandler ABC + curl implementations
│   └── response_serializers/ # ResponseSerializer ABC + JSONDotSerializer
└── reporting/
    ├── generators/         # BaseGenerator ABC + one file per format
    ├── enum/               # GeneratorKey and GeneratorExtension enums
    ├── models/             # SummaryResult dataclass
    └── utils/              # summary.py helper functions

tests/                      # Mirrors src/pentester/ structure exactly
docs/                       # Markdown docs (configuration.md, etc.)
```

---

## Architecture Patterns

### Settings (Pydantic BaseSettings)
- Every settings class extends `pydantic_settings.BaseSettings`.
- Root settings: `PentesterSettings` in `config/settings.py`. Add nested settings blocks there with `Field(default_factory=<SettingsClass>)`.
- Env var naming: `PENTESTER_<FIELD>` at root level, `PENTESTER_<SECTION>__<FIELD>` for nested (double-underscore delimiter).
- Singleton access: `get_settings()` (cached via `@lru_cache`). Tests must call `clear_settings_cache()` in a fixture.

### Factories
- Dict-based lookup: `_auditors: dict[str, BaseAuditor]` keyed by short string name.
- Expose `get_auditor(key)`, `get_auditors(keys)`, `get_available_auditors()`.
- Do not make factories singletons unless there is a strong reason (`GeneratorFactory` is the only existing singleton factory).
- Construction logic belongs inside the class being constructed, not the factory (e.g. `Scanner.from_settings`).

### Abstract Base Classes
- Define the ABC in `models/base_*.py` (e.g. `base_auditor.py`, `base_generator.py`).
- Concrete implementations live one level up (e.g. `auditors/garak.py`).
- All abstract methods and properties must have return type annotations.

### Data Transfer Objects
- Use `@dataclass`, not Pydantic models, for DTOs (`ProbeResult`, `TargetResponse`, `SummaryResult`).

### classmethods for construction
- Named constructors follow the `from_<source>` pattern: `from_curl`, `from_curl_file`, `from_settings`.
- Add a `from_settings(cls, settings: XSettings) -> "ClassName | None"` classmethod whenever a class can be built from a settings object. Return `None` when required config is absent.

---

## Code Style

### Imports
- **Absolute imports only** — never use relative imports.
- Order: stdlib → third-party → local (`pentester.*`).

### Type Annotations
- Use `X | None` (not `Optional[X]`) for nullable types in new code.
- Always annotate return types, including `-> None`.
- Use built-in generics: `list[str]`, `dict[str, X]` (not `List`, `Dict`).
- Target Python 3.11+.

### Naming
| Element | Convention | Example |
|---|---|---|
| Files | `snake_case` | `base_auditor.py` |
| Classes | `PascalCase` | `GarakAuditor` |
| Methods / functions | `snake_case` | `get_available_auditors` |
| Private attributes | `_snake_case` | `self._scanner` |
| Constants | `UPPER_SNAKE` | `_TEMPLATES_DIR` |
| Enum values | `UPPER_SNAKE` | `GeneratorKey.PDF` |
| Settings fields | `snake_case` | `curl_command` |
| Test helpers | `_make_<object>()` | `_make_settings()` |

---

## Test Conventions

- **Mirror structure**: `tests/foo/bar/test_baz.py` covers `src/pentester/foo/bar/baz.py`.
- **Group by feature**: Use `class Test<Feature>:` to group related test methods.
- **One assertion per test** where practical; descriptive method names.
- **Fixtures**: Use `@pytest.fixture(autouse=True)` with `yield` for setup/teardown (e.g. cache resets).
- **Helpers**: `_make_<object>(**kwargs)` factory functions at module level, not fixtures, when creating test data.
- **Mocking external packages** (e.g. `garak`): Stub via `sys.modules` at the top of the test file, before any local imports. Use `# noqa: E402` on imports that must come after the stub block.
- **Singleton resets**: Always provide a `reset_cache` / `reset_singleton` autouse fixture when testing singletons.
- Run `/validate` after every code + test change.

### Dependency mocking (unit test boundary rule)

Tests are strict unit tests. Each test file is responsible only for the class it covers and must treat every dependency as a black box:

- **Mock only the immediate dependencies** of the class under test — never reach inside a dependency to mock its internals.
- Inject dependencies as `MagicMock()` instances; do not instantiate real collaborators.
- Assert on the mock: verify it was called, with what arguments, and that the return value flows through correctly.
- **Never assert on implementation details of a dependency** (e.g. do not check that `ProbeFilter._rules` was set — only check that `ProbeFilter` was called with the right args).

```python
# CORRECT — mock the immediate dependency, treat it as a black box
mock_filter = MagicMock()
mock_filter.apply.return_value = []
probe = MyProbe(filter=mock_filter)
probe.run()
mock_filter.apply.assert_called_once_with(expected_input)

# WRONG — reaching inside the dependency's internals
real_filter = ProbeFilter(rules=[...])   # instantiating a real collaborator
assert real_filter._rules == [...]       # asserting on its private state
```

---

## Adding a New Auditor

1. Create `src/pentester/config/auditors/<name>_settings.py` with a `<Name>Settings(BaseSettings)` class.
2. Add the settings field to `PentesterSettings` in `config/settings.py`.
3. Implement `src/pentester/auditors/<name>.py` extending `BaseAuditor`.
4. Register the auditor in `AuditorFactory.__init__` under its string key.
5. Update `docs/configuration.md` with new env vars.
6. Add tests mirroring the `garak` test structure.

## Adding a New Report Format

1. Add a `GeneratorKey` and `GeneratorExtension` enum value.
2. Create `src/pentester/reporting/generators/<format>_generator.py` extending `BaseGenerator` (or `MakoGenerator` for template-based formats).
3. Register in `GeneratorFactory`.
4. Add tests mirroring existing generator tests.
