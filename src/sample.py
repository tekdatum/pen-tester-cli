"""Manual runner for PyritProbe.

Usage (from the project root with the package installed):

    python sample.py

Override settings via environment variables:

    PENTESTER_PYRIT__DATASET_NAMES='["xstest"]' \\
    PENTESTER_PYRIT__MAX_SEEDS=10               \\
    python sample.py

Prerequisites
-------------
* pyrit must be installed (pip install pyrit)
* tqdm must be installed (pip install tqdm)
* The target HTTP endpoint must be reachable (for SEMANTIC_FENCE target type)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from pentester.auditors.pyrit import PyritProbe  # noqa: E402
from pentester.config.auditors.pyrit_settings import PyritSettings  # noqa: E402
from pentester.reporting import Reporting  # noqa: E402

DATASET_NAMES: list[str] = []  # empty → all datasets; e.g. ["xstest"]
MAX_SEEDS: int | None = 5  # None = all seeds in the dataset
OUTPUT_DIR: str = "./output"
REPORT_FORMATS: list[str] = ["csv", "html", "markdown"]


def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    settings = PyritSettings(dataset_names=DATASET_NAMES, max_seeds=MAX_SEEDS)
    auditor = PyritProbe(settings=settings)
    results = auditor.audit()

    print(f"\nTotal results: {len(results)}")

    Reporting().generate_details(results, OUTPUT_DIR, REPORT_FORMATS)

    print(f"Reports written to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
