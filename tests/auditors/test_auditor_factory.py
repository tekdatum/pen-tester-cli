"""Tests for AuditorFactory.

garak.* and pyrit.* are stubbed via sys.modules so the suite runs without
the real packages present.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub garak and pyrit before any pentester import resolves them.
# ---------------------------------------------------------------------------

_garak_config_mod = MagicMock(name="garak._config")
_garak_plugins_mod = MagicMock(name="garak._plugins")
_garak_command_mod = MagicMock(name="garak.command")
_garak_mod = MagicMock(name="garak")
_garak_mod._config = _garak_config_mod
_garak_mod._plugins = _garak_plugins_mod
_garak_mod.command = _garak_command_mod

_pyrit_setup_mod = MagicMock(name="pyrit.setup")
_pyrit_setup_mod.initialize_pyrit_async = AsyncMock()

_tqdm_stub = MagicMock(name="tqdm")
_tqdm_stub.tqdm = lambda iterable, **_kwargs: iterable

for _name, _stub in [
    ("garak", _garak_mod),
    ("garak._config", _garak_config_mod),
    ("garak._plugins", _garak_plugins_mod),
    ("garak.command", _garak_command_mod),
    ("garak.attempt", MagicMock(name="garak.attempt")),
    ("garak.generators", MagicMock(name="garak.generators")),
    ("garak.generators.litellm", MagicMock(name="garak.generators.litellm")),
    ("garak.generators.openai", MagicMock(name="garak.generators.openai")),
    ("pyrit", MagicMock(name="pyrit")),
    ("pyrit.datasets", MagicMock(name="pyrit.datasets")),
    ("pyrit.executor", MagicMock(name="pyrit.executor")),
    ("pyrit.executor.attack", MagicMock(name="pyrit.executor.attack")),
    ("pyrit.executor.attack.core", MagicMock(name="pyrit.executor.attack.core")),
    (
        "pyrit.executor.attack.multi_turn",
        MagicMock(name="pyrit.executor.attack.multi_turn"),
    ),
    ("pyrit.memory", MagicMock(name="pyrit.memory")),
    ("pyrit.setup", _pyrit_setup_mod),
    ("pyrit.prompt_target", MagicMock(name="pyrit.prompt_target")),
    ("pyrit.score", MagicMock(name="pyrit.score")),
    ("pyrit.score.true_false", MagicMock(name="pyrit.score.true_false")),
    (
        "pyrit.score.true_false.self_ask_true_false_scorer",
        MagicMock(name="pyrit.score.true_false.self_ask_true_false_scorer"),
    ),
    ("pyrit.models", MagicMock(name="pyrit.models")),
    ("pyrit.models.attack_result", MagicMock(name="pyrit.models.attack_result")),
    ("tqdm", _tqdm_stub),
]:
    sys.modules.setdefault(_name, _stub)

from pentester.auditors.auditor_factory import AuditorFactory  # noqa: E402
from pentester.auditors.models.base_auditor import BaseAuditor  # noqa: E402
from pentester.config.settings import PentesterSettings  # noqa: E402
from pentester.scanners.scanner import Scanner  # noqa: E402


@pytest.fixture(autouse=True)
def _patch_promptfoo_auditor():
    """Mock PromptfooAuditor at the factory boundary so its __init__ never runs."""
    with patch("pentester.auditors.auditor_factory.PromptfooAuditor") as mock_cls:
        yield mock_cls


@pytest.fixture(autouse=True)
def _patch_venv_auditor():
    """Mock VenvAuditor at the factory boundary so its __init__ never runs."""
    with patch("pentester.auditors.auditor_factory.VenvAuditor") as mock_cls:
        yield mock_cls


def _make_settings(**scanner_kwargs) -> PentesterSettings:
    from pentester.config.scanner import ScannerSettings

    return PentesterSettings(scanner=ScannerSettings(**scanner_kwargs))


# ---------------------------------------------------------------------------
# _build_scanner
# ---------------------------------------------------------------------------


class TestScannerConstruction:
    def test_returns_none_when_no_curl_command(self) -> None:
        factory = AuditorFactory(_make_settings())
        assert factory._scanner is None

    def test_returns_scanner_when_curl_command_set(self) -> None:
        factory = AuditorFactory(_make_settings(curl_command="curl http://example.com"))
        assert isinstance(factory._scanner, Scanner)

    def test_scanner_has_no_serializer_when_no_json_dot_target(self) -> None:
        factory = AuditorFactory(_make_settings(curl_command="curl http://example.com"))
        assert isinstance(factory._scanner, Scanner)
        assert factory._scanner.request_handler.response_serializer is None

    def test_scanner_has_serializer_when_json_dot_target_set(self) -> None:
        factory = AuditorFactory(
            _make_settings(
                curl_command="curl http://example.com",
                json_dot_target="body.result",
            )
        )
        assert isinstance(factory._scanner, Scanner)
        assert factory._scanner.request_handler.response_serializer is not None


# ---------------------------------------------------------------------------
# Scanner injection into auditors
# ---------------------------------------------------------------------------


class TestScannerInjection:
    def test_garak_auditor_receives_none_scanner_when_not_configured(
        self, _patch_venv_auditor
    ) -> None:
        factory = AuditorFactory(_make_settings())
        factory.get_auditor("garak")
        _, kwargs = _patch_venv_auditor.call_args
        assert kwargs["scanner"] is None

    def test_garak_auditor_receives_scanner_when_configured(
        self, _patch_venv_auditor
    ) -> None:
        factory = AuditorFactory(_make_settings(curl_command="curl http://example.com"))
        factory.get_auditor("garak")
        _, kwargs = _patch_venv_auditor.call_args
        assert isinstance(kwargs["scanner"], Scanner)

    def test_promptfoo_auditor_receives_none_scanner_when_not_configured(
        self, _patch_promptfoo_auditor
    ) -> None:
        factory = AuditorFactory(_make_settings())
        factory.get_auditor("promptfoo")
        _patch_promptfoo_auditor.assert_called_once()
        _, kwargs = _patch_promptfoo_auditor.call_args
        assert kwargs["scanner"] is None

    def test_promptfoo_auditor_receives_scanner_when_configured(
        self, _patch_promptfoo_auditor
    ) -> None:
        factory = AuditorFactory(_make_settings(curl_command="curl http://example.com"))
        factory.get_auditor("promptfoo")
        _patch_promptfoo_auditor.assert_called_once()
        _, kwargs = _patch_promptfoo_auditor.call_args
        assert isinstance(kwargs["scanner"], Scanner)


class TestLLMSettingsInjection:
    def test_promptfoo_auditor_receives_llm_settings_from_factory(
        self, _patch_promptfoo_auditor
    ) -> None:
        settings = _make_settings()
        factory = AuditorFactory(settings)
        factory.get_auditor("promptfoo")
        _, kwargs = _patch_promptfoo_auditor.call_args
        assert kwargs["llm_settings"] is settings.llm

    def test_promptfoo_auditor_receives_target_type_from_factory(
        self, _patch_promptfoo_auditor
    ) -> None:
        from pentester.enums.target_type import TargetType

        settings = _make_settings()
        factory = AuditorFactory(settings)
        factory.get_auditor("promptfoo")
        _, kwargs = _patch_promptfoo_auditor.call_args
        assert kwargs["target_type"] == TargetType.SEMANTIC_FENCE


# ---------------------------------------------------------------------------
# scanner property
# ---------------------------------------------------------------------------


class TestScannerProperty:
    def test_returns_none_when_no_scanner(self) -> None:
        factory = AuditorFactory(_make_settings())
        assert factory.scanner is None

    def test_returns_scanner_when_configured(self) -> None:
        factory = AuditorFactory(_make_settings(curl_command="curl http://example.com"))
        assert isinstance(factory.scanner, Scanner)


# ---------------------------------------------------------------------------
# get_auditor
# ---------------------------------------------------------------------------


class TestGetAuditor:
    def test_get_garak_returns_venv_auditor(self, _patch_venv_auditor) -> None:
        factory = AuditorFactory(_make_settings())
        auditor = factory.get_auditor("garak")
        assert auditor is _patch_venv_auditor.return_value

    def test_get_promptfoo_returns_promptfoo_auditor(
        self, _patch_promptfoo_auditor
    ) -> None:
        factory = AuditorFactory(_make_settings())
        auditor = factory.get_auditor("promptfoo")
        assert auditor is _patch_promptfoo_auditor.return_value

    def test_get_unknown_key_raises(self) -> None:
        factory = AuditorFactory(_make_settings())
        try:
            factory.get_auditor("unknown")
            assert False, "Expected KeyError"
        except KeyError:
            pass


# ---------------------------------------------------------------------------
# get_available_auditors
# ---------------------------------------------------------------------------


class TestGetAvailableAuditors:
    def test_returns_list(self) -> None:
        factory = AuditorFactory(_make_settings())
        assert isinstance(factory.get_available_auditors(), list)

    def test_contains_garak_auditor(self, _patch_venv_auditor) -> None:
        factory = AuditorFactory(_make_settings())
        auditors = factory.get_available_auditors()
        assert _patch_venv_auditor.return_value in auditors

    def test_contains_promptfoo_auditor(self, _patch_promptfoo_auditor) -> None:
        factory = AuditorFactory(_make_settings())
        auditors = factory.get_available_auditors()
        assert _patch_promptfoo_auditor.return_value in auditors

    def test_all_items_are_base_auditors(
        self, _patch_promptfoo_auditor, _patch_venv_auditor
    ) -> None:
        factory = AuditorFactory(_make_settings())
        for auditor in factory.get_available_auditors():
            is_mock = auditor in (
                _patch_promptfoo_auditor.return_value,
                _patch_venv_auditor.return_value,
            )
            is_real = isinstance(auditor, BaseAuditor)
            assert is_real or is_mock


# ---------------------------------------------------------------------------
# get_auditors
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# get_auditors
# ---------------------------------------------------------------------------


class TestGetAuditors:
    def test_returns_requested_auditors(self, _patch_venv_auditor) -> None:
        factory = AuditorFactory(_make_settings())
        result = factory.get_auditors(["garak"])
        assert len(result) == 1
        assert result[0] is _patch_venv_auditor.return_value

    def test_empty_keys_returns_empty_list(self) -> None:
        factory = AuditorFactory(_make_settings())
        assert factory.get_auditors([]) == []

    def test_unknown_key_raises(self) -> None:
        factory = AuditorFactory(_make_settings())
        try:
            factory.get_auditors(["unknown"])
            assert False, "Expected KeyError"
        except KeyError:
            pass
