# Reporting

The reporting module generates audit reports from a list of `ProbeResult` objects. It supports four output formats and produces two types of files per format: a **summary report** aggregating results across all tools, and one **detail report per tool** listing every individual probe.

## Output files

For each selected format, `Reporting.generate` writes the following files to the output directory:

| File | Description |
|------|-------------|
| `summary.{ext}` | Aggregated metrics across all tools with per-tool breakdown |
| `{auditor}_details.{ext}` | Full probe table for a single tool |

The summary file links to each tool's detail file. Each detail file links back to the summary.

## Supported formats

| Key | Extension | Description |
|-----|-----------|-------------|
| `html` | `.html` | Styled HTML with stat cards and tables |
| `pdf` | `.pdf` | Same as HTML, rendered to PDF via WeasyPrint |
| `markdown` | `.md` | Standard Markdown tables |
| `csv` | `.csv` | Comma-separated values |

## Usage

### Basic — generate all formats

```python
from pentester.reporting.reporting import Reporting
from pentester.auditors.models.probe_result import ProbeResult

results: list[ProbeResult] = [...]  # collected from auditors

reporting = Reporting()
reporting.generate(
    data=results,
    output_dir_path="./reports",
    generator_keys=["html", "pdf", "markdown", "csv"],
)
```

The output directory is created automatically if it does not exist.

### Single format

```python
reporting.generate(
    data=results,
    output_dir_path="./reports",
    generator_keys=["markdown"],
)
```

### Selecting specific formats

```python
reporting.generate(
    data=results,
    output_dir_path="./reports/run-01",
    generator_keys=["html", "csv"],
)
```

## Using `Summarizer` directly

The `Summarizer` utility can be used independently to compute metrics without generating files.

```python
from pentester.reporting.utils.summary import Summarizer

# Overall metrics across all probes
overall = Summarizer.summarize(results)
print(overall.total_probes)    # int
print(overall.total_bypassed)  # int
print(overall.success_rate)    # float, e.g. 83.33

# Metrics grouped by tool
by_tool = Summarizer.summarize_by_auditor(results)
for tool, summary in by_tool.items():
    print(f"{tool}: {summary.success_rate}% pass rate")

# Metrics grouped by attack category or type
by_category = Summarizer.summarize_by_attack_category(results)
by_type = Summarizer.summarize_by_attack_type(results)

# Filter probes for a specific tool
garak_results = Summarizer.filter_by_auditor("garak", results)

# List all unique tool names, sorted
tools = Summarizer.unique_auditors(results)
```

## Module structure

```
reporting/
├── reporting.py              # Reporting orchestrator
├── models/
│   └── summary_result.py     # SummaryResult dataclass
├── utils/
│   └── summary.py            # Summarizer utility
├── enum/
│   ├── generator_key.py      # GeneratorKey enum  (pdf, csv, html, markdown)
│   └── generator_extension.py
└── generators/
    ├── base_generator.py     # Abstract base
    ├── mako_generator.py     # Template rendering base
    ├── html_generator.py
    ├── pdf_generator.py
    ├── markdown_generator.py
    ├── csv_generator.py
    ├── generator_factory.py  # Singleton factory
    └── mako/
        ├── summary.html
        ├── summary.md
        ├── summary.csv
        ├── details.html
        ├── details.md
        └── details.csv
```
