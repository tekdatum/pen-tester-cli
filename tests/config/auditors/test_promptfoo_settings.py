from pathlib import Path

import pytest
from pydantic import ValidationError

from pentester.config.auditors.promptfoo_settings import (
    KNOWN_MULTITURN_STRATEGIES,
    PromptfooSettings,
)
from pentester.enums.promptfoo_strategy import PromptfooMultiturnStrategy


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

    def test_max_tests_default(self) -> None:
        settings = PromptfooSettings()
        assert settings.max_tests == 20000

    def test_output_path_default(self) -> None:
        settings = PromptfooSettings()
        assert settings.output_path == "./output/promptfoo"


class TestComputedFields:
    def test_config_file_appends_yaml_filename(self) -> None:
        settings = PromptfooSettings()
        assert settings.config_file.endswith("promptfooconfig.yaml")

    def test_tests_path_is_output_path_plus_tests(self) -> None:
        settings = PromptfooSettings()
        assert settings.tests_path == Path("./output/promptfoo") / "tests"

    def test_tests_path_returns_path_instance(self) -> None:
        settings = PromptfooSettings()
        assert isinstance(settings.tests_path, Path)

    def test_results_path_is_output_path_plus_results(self) -> None:
        settings = PromptfooSettings()
        assert settings.results_path == Path("./output/promptfoo") / "results"

    def test_results_path_returns_path_instance(self) -> None:
        settings = PromptfooSettings()
        assert isinstance(settings.results_path, Path)

    def test_tests_path_configurations_is_subdir_of_tests_path(self) -> None:
        settings = PromptfooSettings()
        assert (
            settings.tests_path_configurations == settings.tests_path / "configurations"
        )

    def test_tests_path_llm_assert_is_subdir_of_tests_path(self) -> None:
        settings = PromptfooSettings()
        assert (
            settings.tests_path_llm_assert
            == settings.tests_path / "llm_as_judge_assert"
        )

    def test_config_file_returns_str_instance(self) -> None:
        settings = PromptfooSettings()
        assert isinstance(settings.config_file, str)

    def test_tests_path_reflects_custom_output_path(self) -> None:
        settings = PromptfooSettings(output_path="/custom/output")
        assert settings.tests_path == Path("/custom/output") / "tests"

    def test_results_path_reflects_custom_output_path(self) -> None:
        settings = PromptfooSettings(output_path="/custom/output")
        assert settings.results_path == Path("/custom/output") / "results"


class TestComputedFieldsWithCustomPath:
    def test_config_file_reflects_custom_path(self) -> None:
        settings = PromptfooSettings(config_path="/custom/path")
        assert settings.config_file == "/custom/path/promptfooconfig.yaml"

    def test_tests_path_is_independent_of_config_path(self) -> None:
        settings = PromptfooSettings(config_path="/custom/path")
        assert settings.tests_path == Path("./output/promptfoo") / "tests"

    def test_results_path_is_independent_of_config_path(self) -> None:
        settings = PromptfooSettings(config_path="/custom/path")
        assert settings.results_path == Path("./output/promptfoo") / "results"

    def test_tests_path_configurations_reflects_custom_output_path(self) -> None:
        settings = PromptfooSettings(output_path="/custom/output")
        assert settings.tests_path_configurations == Path(
            "/custom/output/tests/configurations"
        )

    def test_tests_path_llm_assert_reflects_custom_output_path(self) -> None:
        settings = PromptfooSettings(output_path="/custom/output")
        assert settings.tests_path_llm_assert == Path(
            "/custom/output/tests/llm_as_judge_assert"
        )


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

    def test_set_max_tests(self) -> None:
        settings = PromptfooSettings(max_tests=500)
        assert settings.max_tests == 500

    def test_set_output_path(self) -> None:
        settings = PromptfooSettings(output_path="/my/output")
        assert settings.output_path == "/my/output"

    def test_all_fields_set_together(self) -> None:
        settings = PromptfooSettings(
            config_path="/custom",
            assertion_wrapper_path="/wrap.py",
            replace_existing_file=True,
            files_parallel=3,
            internal_concurrency=2,
            output_path="/my/output",
        )
        assert settings.config_path == "/custom"
        assert settings.assertion_wrapper_path == "/wrap.py"
        assert settings.replace_existing_file is True
        assert settings.files_parallel == 3
        assert settings.internal_concurrency == 2
        assert settings.output_path == "/my/output"


class TestPluginsPerFile:
    def test_default_is_one(self) -> None:
        assert PromptfooSettings().plugins_per_file == 1

    def test_accepts_boundary_values(self) -> None:
        assert PromptfooSettings(plugins_per_file=1).plugins_per_file == 1
        assert PromptfooSettings(plugins_per_file=5).plugins_per_file == 5

    def test_accepts_mid_range(self) -> None:
        assert PromptfooSettings(plugins_per_file=3).plugins_per_file == 3

    def test_rejects_zero(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(plugins_per_file=0)

    def test_rejects_six(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(plugins_per_file=6)

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(plugins_per_file=-1)


class TestMaxTestFiles:
    def test_default_is_none(self) -> None:
        assert PromptfooSettings().max_test_files is None

    def test_accepts_one(self) -> None:
        assert PromptfooSettings(max_test_files=1).max_test_files == 1

    def test_accepts_large_value(self) -> None:
        assert PromptfooSettings(max_test_files=100).max_test_files == 100

    def test_rejects_zero(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(max_test_files=0)

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(max_test_files=-1)


class TestMaxAttacks:
    def test_default_is_none(self) -> None:
        assert PromptfooSettings().max_attacks is None

    def test_accepts_positive_value(self) -> None:
        assert PromptfooSettings(max_attacks=100).max_attacks == 100

    def test_accepts_none_explicitly(self) -> None:
        assert PromptfooSettings(max_attacks=None).max_attacks is None


class TestDefaultEmail:
    def test_default_email_value(self) -> None:
        assert PromptfooSettings().default_email == "tools@tekdatum.com"

    def test_accepts_custom_email(self) -> None:
        settings = PromptfooSettings(default_email="custom@example.com")
        assert settings.default_email == "custom@example.com"

    def test_default_email_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DEFAULT_EMAIL", "env@example.com")
        settings = PromptfooSettings()
        assert settings.default_email == "env@example.com"


class TestEnvVarOverrides:
    def test_config_path_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CONFIG_PATH", "/env/path")
        settings = PromptfooSettings()
        assert settings.config_path == "/env/path"

    def test_assertion_wrapper_path_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ASSERTION_WRAPPER_PATH", "/env/assert.py")
        settings = PromptfooSettings()
        assert settings.assertion_wrapper_path == "/env/assert.py"

    def test_replace_existing_file_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REPLACE_EXISTING_FILE", "true")
        settings = PromptfooSettings()
        assert settings.replace_existing_file is True

    def test_files_parallel_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FILES_PARALLEL", "20")
        settings = PromptfooSettings()
        assert settings.files_parallel == 20

    def test_internal_concurrency_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("INTERNAL_CONCURRENCY", "16")
        settings = PromptfooSettings()
        assert settings.internal_concurrency == 16

    def test_max_tests_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MAX_TESTS", "100")
        settings = PromptfooSettings()
        assert settings.max_tests == 100

    def test_output_path_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OUTPUT_PATH", "/env/output")
        settings = PromptfooSettings()
        assert settings.output_path == "/env/output"


class TestMultiturnDefaults:
    def test_enable_multiturn_default(self) -> None:
        assert PromptfooSettings().enable_multiturn is False

    def test_multiturn_max_turns_default(self) -> None:
        assert PromptfooSettings().multiturn_max_turns == 5

    def test_multiturn_max_backtracks_default(self) -> None:
        assert PromptfooSettings().multiturn_max_backtracks == 5

    def test_multiturn_stateful_default(self) -> None:
        assert PromptfooSettings().multiturn_stateful is False

    def test_multiturn_continue_after_success_default(self) -> None:
        assert PromptfooSettings().multiturn_continue_after_success is False

    def test_multiturn_strategies_default(self) -> None:
        assert set(PromptfooSettings().multiturn_strategies) == set(PromptfooMultiturnStrategy)


class TestMultiturnDirectInit:
    def test_set_enable_multiturn(self) -> None:
        settings = PromptfooSettings(enable_multiturn=True)
        assert settings.enable_multiturn is True

    def test_set_multiturn_max_turns(self) -> None:
        settings = PromptfooSettings(multiturn_max_turns=10)
        assert settings.multiturn_max_turns == 10

    def test_set_multiturn_max_backtracks(self) -> None:
        settings = PromptfooSettings(multiturn_max_backtracks=3)
        assert settings.multiturn_max_backtracks == 3

    def test_set_multiturn_stateful(self) -> None:
        settings = PromptfooSettings(multiturn_stateful=True)
        assert settings.multiturn_stateful is True

    def test_set_multiturn_continue_after_success(self) -> None:
        settings = PromptfooSettings(multiturn_continue_after_success=True)
        assert settings.multiturn_continue_after_success is True

    def test_set_multiturn_strategies_subset(self) -> None:
        settings = PromptfooSettings(multiturn_strategies=["crescendo", "goat"])
        assert settings.multiturn_strategies == [
            PromptfooMultiturnStrategy.CRESCENDO,
            PromptfooMultiturnStrategy.GOAT,
        ]


class TestMultiturnValidation:
    def test_max_turns_rejects_zero(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(multiturn_max_turns=0)

    def test_max_turns_rejects_twenty_one(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(multiturn_max_turns=21)

    def test_max_turns_rejects_negative(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(multiturn_max_turns=-1)

    def test_max_turns_accepts_boundary_one(self) -> None:
        assert PromptfooSettings(multiturn_max_turns=1).multiturn_max_turns == 1

    def test_max_turns_accepts_boundary_twenty(self) -> None:
        assert PromptfooSettings(multiturn_max_turns=20).multiturn_max_turns == 20

    def test_max_backtracks_rejects_zero(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(multiturn_max_backtracks=0)

    def test_max_backtracks_rejects_twenty_one(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(multiturn_max_backtracks=21)

    def test_max_backtracks_accepts_boundary_one(self) -> None:
        assert PromptfooSettings(multiturn_max_backtracks=1).multiturn_max_backtracks == 1

    def test_max_backtracks_accepts_boundary_twenty(self) -> None:
        assert PromptfooSettings(multiturn_max_backtracks=20).multiturn_max_backtracks == 20

    def test_strategies_rejects_unknown_id(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooSettings(multiturn_strategies=["crescendo", "unknown-strategy"])

    def test_strategies_accepts_all_known(self) -> None:
        settings = PromptfooSettings(
            multiturn_strategies=list(KNOWN_MULTITURN_STRATEGIES)
        )
        assert set(settings.multiturn_strategies) == set(PromptfooMultiturnStrategy)

    def test_strategies_accepts_empty_list(self) -> None:
        settings = PromptfooSettings(multiturn_strategies=[])
        assert settings.multiturn_strategies == []


class TestMultiturnEnvVars:
    def test_enable_multiturn_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ENABLE_MULTITURN", "true")
        assert PromptfooSettings().enable_multiturn is True

    def test_multiturn_max_turns_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MULTITURN_MAX_TURNS", "10")
        assert PromptfooSettings().multiturn_max_turns == 10

    def test_multiturn_max_backtracks_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MULTITURN_MAX_BACKTRACKS", "8")
        assert PromptfooSettings().multiturn_max_backtracks == 8

    def test_multiturn_stateful_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MULTITURN_STATEFUL", "true")
        assert PromptfooSettings().multiturn_stateful is True

    def test_multiturn_continue_after_success_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MULTITURN_CONTINUE_AFTER_SUCCESS", "true")
        assert PromptfooSettings().multiturn_continue_after_success is True

    def test_multiturn_strategies_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MULTITURN_STRATEGIES", '["crescendo","goat"]')
        settings = PromptfooSettings()
        assert settings.multiturn_strategies == [
            PromptfooMultiturnStrategy.CRESCENDO,
            PromptfooMultiturnStrategy.GOAT,
        ]
    
    def test_max_attacks_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MAX_ATTACKS", "300")
        settings = PromptfooSettings()
        assert settings.max_attacks == 300
