# Architecture

## Project layout

```
pentester/
├── src/
│   └── pentester/
│       ├── config/
│       ├── probes/
│       ├── scanners/
│       └── reporting/
│           └── generators/
├── test/
├── docs/
├── pyproject.toml
├── requirements.txt
└── publish.sh
```

## Folders

### `src/pentester/`
Root of the installable package. Everything published to PyPI lives here.

### `src/pentester/orchestrator.py`
Manages the scan lifecycle.

### `src/pentester/config/`
User integration with targets and project configuration.

### `src/pentester/probes/`
Defines the attacks that are going to be used.

### `src/pentester/scanners/`
Target communication and response serialization.

### `src/pentester/reporting/`
Configures and manages the available report generators.

### `src/pentester/reporting/generators/`
One generator per output format.

### `test/`
Unit and integration tests. Mirrors the `src/pentester/` structure.

### `docs/`
Project documentation. Each doc covers a specific topic:

| File | Content |
|------|---------|
| `architecture.md` | This file |
| `development.md` | Linter, formatter and test commands |
| `environment.md` | How to set up the local dev environment |
| `logging.md` | Logging configuration and usage |
| `publish.md` | How to publish a new version to PyPI |

### `pyproject.toml`
Single source of truth for the project: metadata, dependencies, build system, and tool configuration (Ruff, Mypy, Pytest).

### `requirements.txt`
Dev and library dependencies.

### `publish.sh`
Script that builds the package, and uploads it to PyPI. See [publish.md](./publish.md).