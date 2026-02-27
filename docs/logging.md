## Logging

This project uses Python's standard `logging` module with a centralized configuration defined in `src/pentester/logging.py`.

The configuration is a hierarchy of loggers rooted at `pentester`. All child loggers (e.g. `pentester.scanner`) inherit the handlers and level from the parent automatically.

```
pentester                ← configured once in setup_logging()
├── pentester.scanner
├── pentester.cli
└── pentester.utils.http
```

### Setup

Call `setup_logging()` once at the CLI entry point. Never call it from library code.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `level` | `int` | `logging.WARNING` | Logging level |
| `log_file` | `bool` | `False` | Write logs to `pentester.log` in addition to stderr |

### Usage

**Entry point:**

```python
import logging
from pentester.logging import setup_logging

def main() -> None:
    setup_logging(level=logging.DEBUG, log_file=True)
```

**Any module inside the package:**

```python
from pentester.logging import get_logger

logger = get_logger(__name__)

def scan(target: str) -> None:
    logger.debug("Starting scan on %s", target)
    logger.info("Scan complete")
    logger.warning("Port 22 open on %s", target)
    logger.error("Connection refused")
```

### Output

Console (`stderr`, simple format):

```
[DEBUG] Starting scan on 192.168.1.1
[WARNING] Port 22 open on 192.168.1.1
```

File (`pentester.log`, full format):

```
2026-02-26T10:00:01 [DEBUG] pentester.scanner: Starting scan on 192.168.1.1
2026-02-26T10:00:01 [WARNING] pentester.scanner: Port 22 open on 192.168.1.1
```

The log file rotates at 10 MB and keeps up to 3 backups.
