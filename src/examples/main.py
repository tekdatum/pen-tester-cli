import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentester.config.logging import setup_logging
from pentester.config.settings import get_settings
from pentester.enums.target_type import TargetType
from pentester.orchestrator import Orchestrator

CURL_COMMAND = (
    "curl -X POST 'http://localhost:8090/api/v1/fence/validate/1'"
    " -H 'Content-Type: application/json'"
    " --data-raw '{\"text\": $PROMPT}'"
)

PROMPTFOO_CURL_COMMAND = (
    "curl -X POST 'http://localhost:8090/api/v1/fence/validate/1'"
    " -H 'Content-Type: application/json'"
    ' --data-raw \'{"text": "{{prompt}}"}\''
)


def main() -> None:
    setup_logging(level=logging.INFO)
    settings = get_settings()

    settings.target_type = TargetType.SEMANTIC_FENCE
    settings.scanner.json_dot_target = "body.data.valid"
    settings.scanner.curl_command = CURL_COMMAND

    # --- Alternative: LLM mode ---
    # settings.target_type = TargetType.LLM
    # settings.llm.provider = LLMProvider.OPENAI
    # settings.llm.model = "gpt-4o-mini"
    # settings.inspect.judge_model = "openai/gpt-4o-mini"

    settings.garak.probes = []

    settings.pyrit.dataset_names = []

    settings.inspect.evals = []

    # Promptfoo — runs all plugins up to max_tests per file
    settings.promptfoo.config_path = "pentester/config/auditor_files/promptfoo"
    settings.promptfoo.assertion_wrapper_path = "assert.py"
    settings.promptfoo.replace_existing_file = False
    settings.promptfoo.files_parallel = 5
    settings.promptfoo.internal_concurrency = 4
    settings.promptfoo.max_tests = 200
    settings.promptfoo.plugins_per_file = 1
    settings.promptfoo.max_test_files = 1
    settings.promptfoo.output_path = "./output/promptfoo"
    settings.promptfoo.enable_multiturn = False

    settings.auditors = ["garak"]

    orchestrator = Orchestrator(settings)
    orchestrator.execute_auditors(settings.auditors)


if __name__ == "__main__":
    main()
