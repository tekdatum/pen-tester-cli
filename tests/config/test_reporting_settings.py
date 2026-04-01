import pytest

from pentester.config.reporting import ReportingSettings
from pentester.reporting.enum.generator_key import GeneratorKey


class TestDefaults:
    def test_output_dir_path_default(self) -> None:
        settings = ReportingSettings()
        assert settings.output_dir_path == "./output/"

    def test_generator_keys_does_not_contain_pdf(self) -> None:
        settings = ReportingSettings()
        assert GeneratorKey.PDF.value not in settings.generator_keys

    def test_generator_keys_contains_csv(self) -> None:
        settings = ReportingSettings()
        assert GeneratorKey.CSV.value in settings.generator_keys

    def test_generator_keys_contains_html(self) -> None:
        settings = ReportingSettings()
        assert GeneratorKey.HTML.value in settings.generator_keys

    def test_generator_keys_contains_markdown(self) -> None:
        settings = ReportingSettings()
        assert GeneratorKey.MARKDOWN.value in settings.generator_keys


class TestEnvVarOverrides:
    def test_output_dir_path_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OUTPUT_DIR_PATH", "/tmp/reports/")
        settings = ReportingSettings()
        assert settings.output_dir_path == "/tmp/reports/"

    def test_generator_keys_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GENERATOR_KEYS", "pdf,csv")
        settings = ReportingSettings()
        assert settings.generator_keys == "pdf,csv"


class TestDirectInit:
    def test_set_output_dir_path(self) -> None:
        settings = ReportingSettings(output_dir_path="/tmp/out/")
        assert settings.output_dir_path == "/tmp/out/"

    def test_set_generator_keys(self) -> None:
        settings = ReportingSettings(generator_keys="html,markdown")
        assert settings.generator_keys == "html,markdown"

    def test_both_fields_set(self) -> None:
        settings = ReportingSettings(
            output_dir_path="/tmp/out/",
            generator_keys="pdf",
        )
        assert settings.output_dir_path == "/tmp/out/"
        assert settings.generator_keys == "pdf"
