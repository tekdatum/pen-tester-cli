"""Tests for AuditorFactory.

garak.* is stubbed via sys.modules so the suite runs without the real package.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, mock_open, patch

import pytest

# ---------------------------------------------------------------------------
# Stub garak before any pentester import resolves it.
# ---------------------------------------------------------------------------

_garak_config_mod = MagicMock(name="garak._config")
_garak_plugins_mod = MagicMock(name="garak._plugins")
_garak_command_mod = MagicMock(name="garak.command")
_garak_mod = MagicMock(name="garak")
_garak_mod._config = _garak_config_mod
_garak_mod._plugins = _garak_plugins_mod
_garak_mod.command = _garak_command_mod

for _name, _stub in [
    ("garak", _garak_mod),
    ("garak._config", _garak_config_mod),
    ("garak._plugins", _garak_plugins_mod),
    ("garak.command", _garak_command_mod),
]:
    sys.modules.setdefault(_name, _stub)

from pentester.auditors.auditor_factory import AuditorFactory  # noqa: E402
from pentester.auditors.garak import GarakAuditor  # noqa: E402
from pentester.auditors.models.base_auditor import BaseAuditor  # noqa: E402
from pentester.auditors.promptfoo.auditor import PromptfooAuditor  # noqa: E402
from pentester.config.settings import PentesterSettings  # noqa: E402
from pentester.scanners.scanner import Scanner  # noqa: E402


_FAKE_PROMPTFOO_CONFIG = {
    "prompts": [],
    "providers": [],
    "redteam": {},
    "defaultTest": [],
    "tests": [],
    "commandLineOptions": [],
    "metadata": {},
}


@pytest.fixture(autouse=True)
def _patch_promptfoo_init():
    """Prevent PromptfooAuditor.__init__ from doing disk I/O in all factory tests."""
    with (
        patch("pathlib.Path.mkdir"),
        patch("builtins.open", mock_open(read_data="")),
        patch(
            "pentester.auditors.promptfoo.auditor.yaml.safe_load",
            return_value=_FAKE_PROMPTFOO_CONFIG,
        ),
    ):
        yield


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
    def test_garak_auditor_receives_none_scanner_when_not_configured(self) -> None:
        factory = AuditorFactory(_make_settings())
        auditor = factory.get_auditor("garak")
        assert auditor._scanner is None

    def test_garak_auditor_receives_scanner_when_configured(self) -> None:
        factory = AuditorFactory(_make_settings(curl_command="curl http://example.com"))
        auditor = factory.get_auditor("garak")
        assert isinstance(auditor._scanner, Scanner)

    def test_promptfoo_auditor_receives_none_scanner_when_not_configured(self) -> None:
        factory = AuditorFactory(_make_settings())
        auditor = factory.get_auditor("promptfoo")
        assert auditor._scanner is None

    def test_promptfoo_auditor_receives_scanner_when_configured(self) -> None:
        factory = AuditorFactory(_make_settings(curl_command="curl http://example.com"))
        auditor = factory.get_auditor("promptfoo")
        assert isinstance(auditor._scanner, Scanner)


# ---------------------------------------------------------------------------
# get_auditor
# ---------------------------------------------------------------------------


class TestGetAuditor:
    def test_get_garak_returns_garak_auditor(self) -> None:
        factory = AuditorFactory(_make_settings())
        assert isinstance(factory.get_auditor("garak"), GarakAuditor)

    def test_get_promptfoo_returns_promptfoo_auditor(self) -> None:
        factory = AuditorFactory(_make_settings())
        assert isinstance(factory.get_auditor("promptfoo"), PromptfooAuditor)

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

    def test_contains_garak_auditor(self) -> None:
        factory = AuditorFactory(_make_settings())
        auditors = factory.get_available_auditors()
        assert any(isinstance(a, GarakAuditor) for a in auditors)

    def test_contains_promptfoo_auditor(self) -> None:
        factory = AuditorFactory(_make_settings())
        auditors = factory.get_available_auditors()
        assert any(isinstance(a, PromptfooAuditor) for a in auditors)

    def test_all_items_are_base_auditors(self) -> None:
        factory = AuditorFactory(_make_settings())
        for auditor in factory.get_available_auditors():
            assert isinstance(auditor, BaseAuditor)


# ---------------------------------------------------------------------------
# get_auditors
# ---------------------------------------------------------------------------


class TestGetAuditors:
    def test_returns_requested_auditors(self) -> None:
        factory = AuditorFactory(_make_settings())
        result = factory.get_auditors(["garak"])
        assert len(result) == 1
        assert isinstance(result[0], GarakAuditor)

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
