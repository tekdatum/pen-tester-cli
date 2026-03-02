# Pentester CLI
SDK

## Claude Code

This project includes custom Claude Code skills. Invoke them with `/skill-name` inside a Claude Code session.

| Skill | Command | Description |
|---|---|---|
| validate | `/validate` | Runs linter (`ruff check`), formatter (`ruff format --check`), type checker (`mypy`), and test suite (`pytest`). Prints a pass/fail table and full output for any failures. |
| pr | `/pr [ticket-url]` | Reads the current branch diff, runs quality checks, and writes a pull request description to `./pr.md`. Accepts an optional ticket URL as argument. |