import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentester.config.logging import setup_logging
from pentester.config.llm import LLMProvider
from pentester.config.settings import get_settings
from pentester.enums.target_type import TargetType
from pentester.orchestrator import Orchestrator

CURL_COMMAND = (
    "curl -X POST 'http://localhost:8090/api/v1/fence/validate/1'"
    " -H 'Content-Type: application/json'"
    " --data-raw '{\"text\": $PROMPT}'"
)


def main() -> None:
    setup_logging(level=logging.INFO)
    settings = get_settings()
    settings.auditors = ["garak", "pyrit"]

    settings.target_type = TargetType.LLM
    settings.llm.provider = LLMProvider.OPENAI
    settings.llm.model = "gpt-4o-mini"
    settings.scanner.curl_command = CURL_COMMAND

    settings.garak.probes = ["probes.dan.Dan_11_0"]
    settings.pyrit.dataset_names = ["psfuzz_steal_system_prompt"]
    settings.inspect.evals = []

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

    orchestrator = Orchestrator(settings)
    orchestrator.execute_auditors(settings.auditors)


if __name__ == "__main__":
    main()
