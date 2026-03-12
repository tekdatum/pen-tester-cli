"""Example: run the PromptFoo auditor end-to-end and generate reports.

Configure via environment variables or a .env file before running:

    PENTESTER_PROMPTFOO__CONFIG_FILE=./promptfooconfig.yaml
    PENTESTER_PROMPTFOO__CONFIG_PATH=./src/pentester/config/auditor_files/promptfoo
    PENTESTER_SCANNER__CURL_COMMAND="curl -X POST http://localhost:8080/chat ..."
    PENTESTER_REPORTING__OUTPUT_DIR_PATH=./output/examples
    PENTESTER_REPORTING__GENERATOR_KEYS=html,csv

Then run:

    python3 -m examples.run_promptfoo
"""

import logging

from pentester.auditors.auditor_factory import AuditorFactory
from pentester.config.logging import setup_logging
from pentester.config.settings import get_settings
from pentester.reporting.reporting import Reporting

setup_logging(level=logging.INFO)

settings = get_settings()

factory = AuditorFactory(settings)
auditor = factory.get_auditor("promptfoo")

results = auditor.audit()
# auditor.results_df = auditor.collector.build_dataframe()
# results = auditor._generate_probe_results()

reporting = Reporting()
generator_keys = [k.strip() for k in settings.reporting.generator_keys.split(",")]
reporting.generate(
    data=results,
    output_dir_path=settings.reporting.output_dir_path,
    generator_keys=generator_keys,
)

print(f"Audit complete with {len(results)} results")
