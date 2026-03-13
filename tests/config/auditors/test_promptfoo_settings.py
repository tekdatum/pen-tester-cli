from pathlib import Path

import pytest

from pentester.config.auditors.promptfoo_settings import PromptfooSettings


class TestDefaults:
    def test_config_path_default(self) -> None:
        settings = PromptfooSettings()
        assert settings.config_path == "./pentester/config/auditor_files/promptfoo"

    def test_assertion_wrapper_path_default(self) -> None:
        settings = PromptfooSettings()
        assert settings.assertion_wrapper_path == "../assert.py"

    def test_replace_existing_file_default(self) -> None:
        settings = PromptfooSettings()
        assert settings.replace_existing_file is False

    def test_files_parallel_default(self) -> None:
        settings = PromptfooSettings()
        assert settings.files_parallel == 5

    def test_internal_concurrency_default(self) -> None:
        settings = PromptfooSettings()
        assert settings.internal_concurrency == 4


class TestComputedFields:
    def test_config_file_appends_yaml_filename(self) -> None:
        settings = PromptfooSettings()
        assert settings.config_file.endswith("promptfooconfig.yaml")

    def test_tests_path_is_config_path_plus_tests(self) -> None:
        settings = PromptfooSettings()
        expected = Path(settings.config_path) / "tests"
        assert settings.tests_path == expected

    def test_tests_path_returns_path_instance(self) -> None:
        settings = PromptfooSettings()
        assert isinstance(settings.tests_path, Path)

    def test_results_path_is_cwd_output_promptfoo_results(self) -> None:
        settings = PromptfooSettings()
        expected = Path.cwd() / "output" / "promptfoo_results"
        assert settings.results_path == expected

    def test_results_path_returns_path_instance(self) -> None:
        settings = PromptfooSettings()
        assert isinstance(settings.results_path, Path)

    def test_tests_path_configurations_is_subdir_of_tests_path(self) -> None:
        settings = PromptfooSettings()
        assert settings.tests_path_configurations == settings.tests_path / "configurations"

    def test_tests_path_llm_assert_is_subdir_of_tests_path(self) -> None:
        settings = PromptfooSettings()
        assert settings.tests_path_llm_assert == settings.tests_path / "llm_as_judge_assert"

    def test_config_file_returns_str_instance(self) -> None:
        settings = PromptfooSettings()
        assert isinstance(settings.config_file, str)


class TestComputedFieldsWithCustomPath:
    def test_config_file_reflects_custom_path(self) -> None:
        settings = PromptfooSettings(config_path="/custom/path")
        assert settings.config_file == "/custom/path/promptfooconfig.yaml"

    def test_tests_path_reflects_custom_path(self) -> None:
        settings = PromptfooSettings(config_path="/custom/path")
        assert settings.tests_path == Path("/custom/path/tests")

    def test_results_path_is_independent_of_config_path(self) -> None:
        settings = PromptfooSettings(config_path="/custom/path")
        assert settings.results_path == Path.cwd() / "output" / "promptfoo_results"

    def test_tests_path_configurations_reflects_custom_path(self) -> None:
        settings = PromptfooSettings(config_path="/custom/path")
        assert settings.tests_path_configurations == Path("/custom/path/tests/configurations")

    def test_tests_path_llm_assert_reflects_custom_path(self) -> None:
        settings = PromptfooSettings(config_path="/custom/path")
        assert settings.tests_path_llm_assert == Path("/custom/path/tests/llm_as_judge_assert")


class TestDirectInit:
    def test_set_config_path(self) -> None:
        settings = PromptfooSettings(config_path="/my/path")
        assert settings.config_path == "/my/path"

    def test_set_assertion_wrapper_path(self) -> None:
        settings = PromptfooSettings(assertion_wrapper_path="/my/assert.py")
        assert settings.assertion_wrapper_path == "/my/assert.py"

    def test_set_replace_existing_file_true(self) -> None:
        settings = PromptfooSettings(replace_existing_file=True)
        assert settings.replace_existing_file is True

    def test_set_files_parallel(self) -> None:
        settings = PromptfooSettings(files_parallel=10)
        assert settings.files_parallel == 10

    def test_set_internal_concurrency(self) -> None:
        settings = PromptfooSettings(internal_concurrency=8)
        assert settings.internal_concurrency == 8

    def test_all_fields_set_together(self) -> None:
        settings = PromptfooSettings(
            config_path="/custom",
            assertion_wrapper_path="/wrap.py",
            replace_existing_file=True,
            files_parallel=3,
            internal_concurrency=2,
        )
        assert settings.config_path == "/custom"
        assert settings.assertion_wrapper_path == "/wrap.py"
        assert settings.replace_existing_file is True
        assert settings.files_parallel == 3
        assert settings.internal_concurrency == 2


class TestEnvVarOverrides:
    def test_config_path_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONFIG_PATH", "/env/path")
        settings = PromptfooSettings()
        assert settings.config_path == "/env/path"

    def test_assertion_wrapper_path_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ASSERTION_WRAPPER_PATH", "/env/assert.py")
        settings = PromptfooSettings()
        assert settings.assertion_wrapper_path == "/env/assert.py"

    def test_replace_existing_file_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("REPLACE_EXISTING_FILE", "true")
        settings = PromptfooSettings()
        assert settings.replace_existing_file is True

    def test_files_parallel_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FILES_PARALLEL", "20")
        settings = PromptfooSettings()
        assert settings.files_parallel == 20

    def test_internal_concurrency_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("INTERNAL_CONCURRENCY", "16")
        settings = PromptfooSettings()
        assert settings.internal_concurrency == 16
