import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentester.config.llm import LLMProvider
from pentester.config.logging import setup_logging
from pentester.config.settings import get_settings
from pentester.enums.attack_strategy import MultiTurnStrategy
from pentester.enums.target_type import TargetType
from pentester.orchestrator import Orchestrator


def _curl_command() -> str:
    api_key = os.environ.get("OPENAI_API_KEY", "")
    return (
        "curl https://api.openai.com/v1/chat/completions"
        " -H 'Content-Type: application/json'"
        f" -H 'Authorization: Bearer {api_key}'"
        ' --data-raw \'{"model": "gpt-4o-mini",'
        ' "messages": [{"role": "user", "content": $PROMPT}]}\''
    )


def main() -> None:
    setup_logging(level=logging.INFO)
    settings = get_settings()
    settings.auditors = ["garak", "pyrit"]

    settings.target_type = TargetType.LLM
    settings.llm.provider = LLMProvider.OPENAI
    settings.llm.model = "gpt-4o-mini"
    settings.scanner.curl_command = _curl_command()
    settings.scanner.response_text_target = "body.choices.0.message.content"

    settings.garak.probes = ["probes.dan.Dan_11_0"]

    settings.pyrit.dataset_names = ["psfuzz_steal_system_prompt"]
    settings.pyrit.enable_multiturn = True
    settings.pyrit.attack_strategies = [MultiTurnStrategy.MULTI_PROMPT_SENDING]
    settings.pyrit.multiturn_objective = "bypass safety filters"

    orchestrator = Orchestrator(settings)
    orchestrator.execute_auditors(settings.auditors)


if __name__ == "__main__":
    main()
