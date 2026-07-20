# User Guide

Task-oriented documentation for people who want to **use** Pentester CLI to scan an
AI system, not modify its source. Start here if this is your first time.

The top-level [`README.md`](../../README.md) is the complete *reference* (every flag,
every environment variable). The guides below are the *narrative* — they walk you
through real scans step by step and explain the "why" behind each setting.

---

## Where to start

Read them in this order the first time. After that, treat them as a menu.

| # | Guide | Read it when you want to… | Time |
|---|---|---|---|
| 1 | [Getting Started](./getting-started.md) | Install the tool and run your very first scan end to end. | ~10 min |
| 2 | [Core Concepts](./concepts.md) | Build the mental model: how a scan actually flows, and the two decisions you always have to make. | ~10 min |
| 3 | [A Full Run](./full-run.md) | Run every auditor against a real target — a semantic fence and an LLM — and read the reports. | ~30 min |
| 4 | [Configuration Recipes](./env-examples.md) | Grab a complete, copy-pasteable `.env.local` for your exact scenario (incl. every promptfoo key). | as needed |
| 5 | [Troubleshooting](./troubleshooting.md) | Fix a scan that errored, hung, or produced empty reports. | as needed |

> **New here?** Do [Getting Started](./getting-started.md) first, run one small scan,
> *then* read [Core Concepts](./concepts.md). The concepts land better once you've
> seen a real report.

---

## The 30-second version

Pentester CLI runs automated adversarial attacks against an AI system and tells you
which ones got through. To run a scan you only ever decide two things:

1. **How do I reach your target?** — a `curl` command (with a `$PROMPT` placeholder),
   a curl file, or a Python custom handler.
2. **How do I know an attack succeeded?** — read a field from the target's JSON
   response (a *semantic fence*), or let a judge model grade the reply (an *LLM*).

Everything else has a default. [Core Concepts](./concepts.md) unpacks both decisions.

---

## Reference docs (deeper dives)

When a guide sends you looking for detail, these are the reference pages:

- [Configuration](../configuration.md) — every setting and `.env` behavior
- [Scanner](../scanner.md) — how requests reach your target
- [Reporting](../reporting.md) — report formats and layout
- [Environment setup](../environment.md) — building a dev virtual environment
- Per-auditor detail: [garak](../auditors/garak.md) · [PyRIT](../auditors/pyrit.md) · [Inspect AI](../auditors/inspect_ai.md) · [Promptfoo](../promptfoo.md) · [Venv isolation](../auditors/venv.md)
