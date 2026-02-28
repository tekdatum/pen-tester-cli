---
name: pr
description: Generate a ./pr.md pull request description from the current git changes. Accepts an optional ticket URL.
argument-hint: [ticket-url]
allowed-tools: Read, Glob, Grep, Bash, Write, Edit
---

Generate a pull request description for the current branch and write it to `./pr.md`.

Ticket URL (may be empty if not provided): $ARGUMENTS

## Steps

### 1. Understand the changes

Run the following to understand what this branch has changed:

- `git diff main...HEAD` — full diff against main
- `git log main...HEAD --oneline` — commits on this branch
- `git diff main...HEAD --name-only` — list of changed files

Read any new or modified source files that are relevant to understanding the feature. Focus on understanding *what* was built and *why*, not just which files changed.

### 2. Run quality checks and capture output

Run each command and capture its output for the Evidence section:

- `ruff check src/` — linter
- `ruff format --check src/` — formatter
- `mypy ./src` — type checker
- `pytest tests/ -v` — test suite (capture the final summary line only, e.g. `49 passed in 0.07s`)

### 3. Determine the type of change

Based on the diff, select **all that apply** from: Bug fix, Feature, Refactor, Docs.

### 4. Determine quality checks

Mark a quality check as complete (`[x]`) only when you have evidence for it:

- **Self-review** — always checked when generating this PR
- **Linter, type checker and formatter** — check only if all three passed with zero errors
- **Applications runs normally** — leave unchecked unless there is a CLI entry point that was verified
- **Common security vulnerabilities** — check if the diff introduces no user-facing input handling, external calls, or secrets
- **Updated relevant documentation** — check only if doc files were modified in the diff

### 5. Write ./pr.md

Use the template below exactly. Fill every section; do not leave any placeholder comments in the final output.

For the **Description**: one concise sentence stating what this PR does.

For the **Changes**: one to three paragraphs in plain prose (no bullet lists, no file names) explaining what is new — the concepts introduced, how they relate to each other, and why they were built this way.

For the **Evidence**: paste the actual terminal output from step 2, formatted as a code block.

---

## Template

```markdown
## Description
{one-sentence description}

## Ticket URL
[Trello]({ticket url or "N/A" if none provided})

## Changes

{prose paragraphs explaining the changes}

## Evidence

\`\`\`
{captured command output}
\`\`\`

## Type of change
- [ ] Bug fix
- [ ] Feature
- [ ] Refactor
- [ ] Docs

## Quality check
- [ ] I have performed a self-review of my code
- [ ] My code passes the linter, type checker and formatter
- [ ] I have checked that the applications runs normally
- [ ] I have considered common security vulnerabilities
- [ ] I have updated relevant documentation
```
