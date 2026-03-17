"""Main entry point — runs both Garak and PyRIT auditors through the Orchestrator.

Usage (from the project root with the package installed):

    python src/sample.py

Override settings via environment variables:

    # SEMANTIC_FENCE mode (default) — route prompts through an HTTP scanner:
    PENTESTER_TARGET_TYPE=SEMANTIC_FENCE              \\
    PENTESTER_SCANNER__CURL_COMMAND='curl ...'        \\
    PENTESTER_PYRIT__DATASET_NAMES='["xstest"]'      \\
    PENTESTER_PYRIT__MAX_SEEDS=10                     \\
    python src/sample.py

    # LLM mode — send prompts directly to a model and score responses:
    PENTESTER_TARGET_TYPE=LLM                         \\
    PENTESTER_LLM__PROVIDER=openai                    \\
    PENTESTER_LLM__MODEL=gpt-4o                       \\
    PENTESTER_PYRIT__DATASET_NAMES='["xstest"]'      \\
    PENTESTER_PYRIT__MAX_SEEDS=5                      \\
    PENTESTER_GARAK__PROBES='["probes.dan.Dan_6_2"]' \\
    python src/sample.py

    # Anthropic (Claude) — uses OpenAI-compatible endpoint:
    PENTESTER_TARGET_TYPE=LLM                         \\
    PENTESTER_LLM__PROVIDER=anthropic                 \\
    PENTESTER_LLM__MODEL=claude-3-5-sonnet-20241022   \\
    ANTHROPIC_API_KEY=<your-key>                      \\
    python src/sample.py

    # Gemini — uses OpenAI-compatible endpoint:
    PENTESTER_TARGET_TYPE=LLM                         \\
    PENTESTER_LLM__PROVIDER=gemini                    \\
    PENTESTER_LLM__MODEL=gemini-1.5-pro               \\
    GEMINI_API_KEY=<your-key>                         \\
    python src/sample.py

Prerequisites
-------------
* garak must be installed (pip install garak)
* pyrit must be installed (pip install pyrit)
* tqdm must be installed (pip install tqdm)
* SEMANTIC_FENCE: the target HTTP endpoint must be reachable
* LLM: the appropriate API key env var must be set for the chosen provider
"""

import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from pentester.config.llm import LLMProvider
from pentester.config.logging import setup_logging
from pentester.config.settings import get_settings  # noqa: E402
from pentester.enums.target_type import TargetType  # noqa: E402
from pentester.orchestrator import Orchestrator  # noqa: E402


def main() -> None:
    setup_logging(level=logging.DEBUG)
    settings = get_settings()
    # settings.auditors = ["garak", "pyrit"]
    settings.auditors = ["pyrit"]
    settings.garak.probes = [
        "probes.test.Test",
    ]
    settings.pyrit.dataset_names = ["psfuzz_steal_system_prompt"]
    settings.llm.provider = LLMProvider.ANTHROPIC
    settings.llm.model = "claude-sonnet-4-6"
    settings.target_type = TargetType.LLM
    orchestrator = Orchestrator(settings)
    orchestrator.execute_auditors(settings.auditors)
    # orchestrator.execute()


if __name__ == "__main__":
    main()
