from pentester.enums.auditor_key import AuditorKey


# ── AuditorKey ────────────────────────────────────────────────────────────────


def test_garak_value() -> None:
    assert AuditorKey.GARAK == "garak"


def test_pyrit_value() -> None:
    assert AuditorKey.PYRIT == "pyrit"


def test_promptfoo_value() -> None:
    assert AuditorKey.PROMPTFOO == "promptfoo"


def test_inspect_ai_value() -> None:
    assert AuditorKey.INSPECT_AI == "inspect_ai"
