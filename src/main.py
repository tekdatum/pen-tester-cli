import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentester.config.llm import LLMProvider
from pentester.config.logging import setup_logging
from pentester.config.settings import get_settings
from pentester.enums.target_type import TargetType
from pentester.orchestrator import Orchestrator


def main() -> None:
    setup_logging(level=logging.INFO)
    settings = get_settings()
    settings.target_type = TargetType.LLM
    settings.auditors = ["garak"]
    settings.garak.probes = ["probes.dan.DanInTheWild"]
    settings.garak.max_attacks = 20
    settings.llm.provider = LLMProvider.OPENAI
    settings.llm.model = "gpt-4o-mini"

    orchestrator = Orchestrator(settings)
    orchestrator.execute_auditors(settings.auditors)


if __name__ == "__main__":
    main()
