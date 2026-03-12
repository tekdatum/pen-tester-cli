"""Example: run the PromptFoo auditor end-to-end and generate reports.

The curl command is set directly in this file via the CURL_COMMAND constant.
Configure the remaining options via environment variables or a .env file before running:

    PENTESTER_PROMPTFOO__CONFIG_FILE=./promptfooconfig.yaml
    PENTESTER_PROMPTFOO__CONFIG_PATH=./src/pentester/config/auditor_files/promptfoo
    PENTESTER_REPORTING__OUTPUT_DIR_PATH=./output/examples
    PENTESTER_REPORTING__GENERATOR_KEYS=html,csv

Then run:

    python3 -m examples.run_promptfoo
"""

import logging

from pentester.auditors.promptfoo.auditor import PromptfooAuditor
from pentester.config.logging import setup_logging
from pentester.config.settings import get_settings
from pentester.reporting.reporting import Reporting
from pentester.scanners.scanner import Scanner

setup_logging(level=logging.INFO)
CURL_COMMAND = (
    "curl -X POST 'http://localhost:8090/api/v1/fence/validate/2'"
    " -H 'Content-Type: application/json'"
    " --data-raw '{\"text\": $PROMPT}'"
)

settings = get_settings()
scanner = Scanner.from_curl(CURL_COMMAND)
auditor = PromptfooAuditor(settings=settings.promptfoo, scanner=scanner)

# results = auditor.audit()
auditor.results_df = auditor.collector.build_dataframe()
results = auditor._generate_probe_results()

reporting = Reporting()
generator_keys = [k.strip() for k in settings.reporting.generator_keys.split(",")]
reporting.generate(
    data=results,
    output_dir_path=settings.reporting.output_dir_path,
    generator_keys=generator_keys,
)

output_dir = settings.reporting.output_dir_path
print(f"Audit complete. {len(results)} probe results written to {output_dir}")
