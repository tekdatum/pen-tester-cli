---
name: validate
description: Run linter, formatter, type checker, and test suite and report results.
allowed-tools: Bash
---

Run all quality checks and report a clear pass/fail summary.

## Steps

### 1. Run all checks in parallel

Run each of the following commands and capture their full output and exit codes:

- `ruff check src/` — linter
- `ruff format --check src/` — formatter
- `mypy ./src` — type checker
- `pytest tests/ -v` — test suite

### 2. Report results

Print a summary table like this, marking each check as PASS or FAIL based on the exit code:

```
| Check       | Result |
|-------------|--------|
| Linter      | PASS   |
| Formatter   | PASS   |
| Type checker| PASS   |
| Tests       | PASS   |
```

After the table:
- If **all checks pass**: print a single line — `All checks passed.`
- If **any check fails**: print the full output of every failing check so the user can act on the errors. End with — `X check(s) failed.`
