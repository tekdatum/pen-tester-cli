"""Example: run the Garak auditor through the Orchestrator.

Configure via environment variables or a .env file:

    PENTESTER_TARGET_TYPE=LLM
    PENTESTER_LLM__PROVIDER=openai
    PENTESTER_LLM__MODEL=gpt-4o
    OPENAI_API_KEY=<your-key>
    PENTESTER_GARAK__PROBES='["probes.dan.Dan_6_2"]'
    PENTESTER_MAX_ATTACKS=10
    PENTESTER_REPORTING__OUTPUT_DIR_PATH=./output/examples
    PENTESTER_REPORTING__GENERATOR_KEYS=html,csv

Then run:

    python3 -m examples.run_garak
"""

import logging

from pentester.config.llm import LLMProvider
from pentester.config.logging import setup_logging
from pentester.config.settings import get_settings
from pentester.enums.target_type import TargetType
from pentester.orchestrator import Orchestrator

setup_logging(level=logging.INFO)

settings = get_settings()
settings.auditors = ["garak"]
settings.target_type = TargetType.LLM
settings.llm.provider = LLMProvider.GEMINI
settings.llm.model = "gemini-2.5-flash-lite"
settings.max_attacks = 10
settings.garak.probes = ["probes.dan.Dan_6_2"]

orchestrator = Orchestrator(settings)
orchestrator.execute_auditors(settings.auditors)
