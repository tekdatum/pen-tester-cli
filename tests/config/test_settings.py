from pathlib import Path

import pytest
from pydantic import ValidationError

from pentester.config.reporting import ReportingSettings
from pentester.config.scanner import ScannerSettings
from pentester.config.settings import (
    PentesterSettings,
    TargetType,
    clear_settings_cache,
    get_settings,
)


@pytest.fixture(autouse=True)
def reset_cache() -> None:
    """Clear the settings singleton before and after each test."""
    clear_settings_cache()
    yield
    clear_settings_cache()


class TestDefaults:
    def test_default_output_dir(self) -> None:
        settings = PentesterSettings()
        assert settings.output_dir == Path("./output")

    def test_default_target_type(self) -> None:
        settings = PentesterSettings()
        assert settings.target_type == TargetType.SEMANTIC_FENCE

    def test_default_scanner_is_scanner_settings(self) -> None:
        settings = PentesterSettings()
        assert isinstance(settings.scanner, ScannerSettings)

    def test_default_scanner_curl_command_is_none(self) -> None:
        settings = PentesterSettings()
        assert settings.scanner.curl_command is None

    def test_default_scanner_json_dot_target_is_none(self) -> None:
        settings = PentesterSettings()
        assert settings.scanner.json_dot_target is None

    def test_default_reporting_is_reporting_settings(self) -> None:
        settings = PentesterSettings()
        assert isinstance(settings.reporting, ReportingSettings)

    def test_default_reporting_output_dir_path(self) -> None:
        settings = PentesterSettings()
        assert settings.reporting.output_dir_path == "./output/"

    def test_default_reporting_generator_keys_contains_all_keys(self) -> None:
        settings = PentesterSettings()
        for key in ("pdf", "csv", "html", "markdown"):
            assert key in settings.reporting.generator_keys


class TestScannerEnvVarOverrides:
    def test_scanner_curl_command_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PENTESTER_SCANNER__CURL_COMMAND", "curl http://example.com")
        settings = PentesterSettings()
        assert settings.scanner.curl_command == "curl http://example.com"

    def test_scanner_json_dot_target_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PENTESTER_SCANNER__JSON_DOT_TARGET", "body.result")
        settings = PentesterSettings()
        assert settings.scanner.json_dot_target == "body.result"


class TestEnvVarOverrides:
    def test_override_output_dir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENTESTER_OUTPUT_DIR", "/tmp/results")
        settings = PentesterSettings()
        assert settings.output_dir == Path("/tmp/results")

    def test_override_target_type_network(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PENTESTER_TARGET_TYPE", "SEMANTIC_FENCE")
        settings = PentesterSettings()
        assert settings.target_type == TargetType.SEMANTIC_FENCE

    def test_override_target_type_llm(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENTESTER_TARGET_TYPE", "LLM")
        settings = PentesterSettings()
        assert settings.target_type == TargetType.LLM

    def test_invalid_target_type_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENTESTER_TARGET_TYPE", "invalid_value")
        with pytest.raises(ValidationError):
            PentesterSettings()

    def test_path_coercion_from_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENTESTER_OUTPUT_DIR", "/tmp/out")
        settings = PentesterSettings()
        assert settings.output_dir == Path("/tmp/out")
        assert isinstance(settings.output_dir, Path)


class TestReportingEnvVarOverrides:
    def test_reporting_output_dir_path_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PENTESTER_REPORTING__OUTPUT_DIR_PATH", "/tmp/reports/")
        settings = PentesterSettings()
        assert settings.reporting.output_dir_path == "/tmp/reports/"

    def test_reporting_generator_keys_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PENTESTER_REPORTING__GENERATOR_KEYS", "pdf,csv")
        settings = PentesterSettings()
        assert settings.reporting.generator_keys == "pdf,csv"


class TestEnvFileLoading:
    def test_env_file_loaded(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("PENTESTER_OUTPUT_DIR=/tmp/from-env\n")
        settings = PentesterSettings(_env_file=str(env_file))
        assert settings.output_dir == Path("/tmp/from-env")

    def test_env_local_overrides_env(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_local_file = tmp_path / ".env.local"
        env_file.write_text("PENTESTER_OUTPUT_DIR=/tmp/from-env\n")
        env_local_file.write_text("PENTESTER_OUTPUT_DIR=/tmp/from-env-local\n")
        settings = PentesterSettings(_env_file=[str(env_file), str(env_local_file)])
        assert settings.output_dir == Path("/tmp/from-env-local")


class TestSettingsSingleton:
    def test_get_settings_returns_instance(self) -> None:
        settings = get_settings()
        assert isinstance(settings, PentesterSettings)

    def test_get_settings_is_cached(self) -> None:
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2

    def test_clear_settings_cache_resets_singleton(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        s1 = get_settings()
        clear_settings_cache()
        monkeypatch.setenv("PENTESTER_OUTPUT_DIR", "/tmp/new-value")
        s2 = get_settings()
        assert s1 is not s2
        assert s2.output_dir == Path("/tmp/new-value")


class TestTargetTypeEnum:
    @pytest.mark.parametrize("member", list(TargetType))
    def test_enum_integrity(self, member):
        """
        Validates two things for every member:
        1. It is an instance of a string.
        2. The value is exactly equal to the variable name.
        """
        assert isinstance(member, str), f"{member.name} is not a string"
        assert member.value == member.name, (
            f"Value mismatch for '{member.name}': "
            f"expected '{member.name}', got '{member.value}'"
        )
