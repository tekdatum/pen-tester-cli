from __future__ import annotations

import copy
import os
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from pentester.auditors.models.probe_result import ProbeResult
from pentester.auditors.promptfoo.auditor import PromptfooAuditor
from pentester.auditors.promptfoo.runner import PromptfooRunner
from pentester.config.auditors.promptfoo_settings import (
    KNOWN_MULTITURN_STRATEGIES,
    PromptfooSettings,
)
from pentester.config.settings import TargetType
from pentester.enums.auditor_key import AuditorKey
from pentester.enums.prompt_type import PromptType
from pentester.scanners.request_handlers.curl_handlers.curl_handler import CurlHandler
from pentester.scanners.response_serializers.json_dot_serializer import (
    JSONDotSerializer,
)


_FAKE_CONFIG: dict[str, Any] = {
    "prompts": ["You are a helpful assistant"],
    "providers": [
        {"id": "http", "config": {"url": "http://example.com", "method": "POST"}}
    ],
    "redteam": {
        "strategies": [
            {"id": "basic"},
            {"id": "jailbreak"},
            {
                "id": "crescendo",
                "config": {
                    "maxTurns": 5,
                    "maxBacktracks": 5,
                    "stateful": False,
                    "continueAfterSuccess": False,
                },
            },
            {
                "id": "goat",
                "config": {
                    "maxTurns": 5,
                    "stateful": False,
                    "continueAfterSuccess": False,
                },
            },
            {"id": "crescendo", "config": {"maxTurns": 5}},
            {"id": "mischievous-user", "config": {"maxTurns": 5, "stateful": False}},
        ],
        "plugins": ["harmful:hate", "harmful:violent-crime"],
        "defaultAssertions": [{"type": "llm-rubric"}],
    },
    "defaultTest": {"assert": [{"type": "is-json"}]},
    "tests": [
        {"vars": {"input": "test1"}, "assert": [{"type": "is-json"}]},
        {"vars": {"input": "test2"}, "assert": [{"type": "is-json"}]},
    ],
    "commandLineOptions": {"maxConcurrency": 4},
    "metadata": {"version": "1.0"},
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(**kwargs: object) -> PromptfooSettings:
    defaults: dict[str, object] = {"config_path": "/tmp/promptfoo_test"}
    defaults.update(kwargs)
    return PromptfooSettings(**defaults)


def _make_scanner_with_dot_target(target: str) -> MagicMock:
    handler = MagicMock()
    handler.response_serializer = JSONDotSerializer(target)
    scanner = MagicMock()
    scanner.request_handler = handler
    return scanner


def _make_auditor(
    settings: PromptfooSettings | None = None,
    scanner: object = None,
    target_type: TargetType = TargetType.SEMANTIC_FENCE,
) -> PromptfooAuditor:
    s = settings or _make_settings()
    mock_cm = MagicMock()
    mock_cm.config = copy.deepcopy(_FAKE_CONFIG)
    with (
        patch("pathlib.Path.mkdir"),
        patch(
            "pentester.auditors.promptfoo.auditor.PromptfooConfigManager",
            return_value=mock_cm,
        ),
    ):
        return PromptfooAuditor(
            settings=s,
            scanner=scanner,
            target_type=target_type,
        )


# ---------------------------------------------------------------------------
# TestInit & TestEnsureDirectories
# ---------------------------------------------------------------------------


class TestInit:
    def test_initializes_with_explicit_settings(self) -> None:
        s = _make_settings(
            config_path="/custom", files_parallel=7, internal_concurrency=3
        )
        auditor = _make_auditor(s)

        assert auditor.settings is s
        assert auditor.runner.results_path == Path("./output/promptfoo") / "results"
        assert auditor.runner.files_parallel == 7
        assert auditor.runner.concurrency == 3
        assert auditor.collector.results_path == Path("./output/promptfoo") / "results"
        assert isinstance(auditor.results_df, pd.DataFrame)
        assert len(auditor.results_df) == 0

    def test_initializes_with_default_settings_when_none_provided(self) -> None:
        mock_cm = MagicMock()
        mock_cm.config = copy.deepcopy(_FAKE_CONFIG)
        with (
            patch("pathlib.Path.mkdir"),
            patch(
                "pentester.auditors.promptfoo.auditor.PromptfooConfigManager",
                return_value=mock_cm,
            ),
        ):
            auditor = PromptfooAuditor(settings=None)

        assert isinstance(auditor.settings, PromptfooSettings)

    def test_scanner_defaults_to_none(self) -> None:
        auditor = _make_auditor()
        assert auditor._scanner is None

    def test_scanner_is_stored_when_provided(self) -> None:
        mock_scanner = MagicMock()
        auditor = _make_auditor(scanner=mock_scanner)
        assert auditor._scanner is mock_scanner


class TestEnsureDirectories:
    def test_creates_required_directories_with_correct_flags(self) -> None:
        mock_cm = MagicMock()
        mock_cm.config = copy.deepcopy(_FAKE_CONFIG)
        with (
            patch("pathlib.Path.mkdir") as mock_mkdir,
            patch(
                "pentester.auditors.promptfoo.auditor.PromptfooConfigManager",
                return_value=mock_cm,
            ),
        ):
            PromptfooAuditor(settings=_make_settings())

        assert mock_mkdir.call_count == 4
        for call_obj in mock_mkdir.call_args_list:
            assert call_obj[1].get("parents") is True
            assert call_obj[1].get("exist_ok") is True


class TestOpenConfig:
    def test_sets_all_config_attributes(self) -> None:
        # _open_config is called during init; config comes from config_manager.config
        auditor = _make_auditor()

        assert isinstance(auditor.config, dict)
        assert auditor.prompts == _FAKE_CONFIG["prompts"]
        assert auditor.providers == _FAKE_CONFIG["providers"]
        assert auditor.redteam == _FAKE_CONFIG["redteam"]
        assert auditor.defaultTest == _FAKE_CONFIG["defaultTest"]
        assert auditor.tests == _FAKE_CONFIG["tests"]
        assert auditor.commandLineOptions == _FAKE_CONFIG["commandLineOptions"]
        assert auditor.metadata == _FAKE_CONFIG["metadata"]


# ---------------------------------------------------------------------------
# Test Plugin Configs & Redteam Generation
# ---------------------------------------------------------------------------


class TestRunRedteamGenerateForConfigs:
    def test_calls_runner_for_all_configs_handling_replace_setting(
        self, tmp_path: Path
    ) -> None:
        configs_dir = tmp_path / "configurations"
        llm_dir = tmp_path / "llm_assert"
        configs_dir.mkdir()
        llm_dir.mkdir()

        (configs_dir / "test_1.yaml").write_text("data")
        (configs_dir / "test_2.yaml").write_text("data")

        auditor = _make_auditor(_make_settings(replace_existing_file=False))
        auditor.runner = MagicMock()

        # If replace is false and output exists, it should skip.
        (llm_dir / "test_1.yaml").write_text("existing output")

        auditor._run_redteam_generate_for_configs(configs_dir, llm_dir)

        # test_1 was skipped, test_2 was generated
        assert auditor.runner.run_redteam_generate.call_count == 1
        call_args = auditor.runner.run_redteam_generate.call_args
        assert call_args[0][1] == llm_dir / "test_2.yaml"


class TestGenerateTestsFiles:
    def test_orchestrates_plugin_writing_and_generation(self) -> None:
        auditor = _make_auditor()
        with patch.object(
            auditor, "_run_redteam_generate_for_configs"
        ) as mock_gen:
            auditor.generate_tests_files()

        auditor.config_manager.write_plugin_configs.assert_called_once()
        assert (
            auditor.config_manager.write_plugin_configs.call_args[0][0]
            == _FAKE_CONFIG["redteam"]["plugins"]
        )
        mock_gen.assert_called_once()

    def test_configures_provider_in_configurations_and_llm_assert_dirs(self) -> None:
        auditor = _make_auditor()
        auditor._scanner = MagicMock()
        auditor.provider_id = "http"

        configurations_dir = auditor.settings.tests_path / "configurations"
        llm_assert_dir = auditor.settings.tests_path / "llm_as_judge_assert"

        with patch.object(auditor, "_run_redteam_generate_for_configs"):
            auditor.generate_tests_files()

        assert auditor.config_manager.configure_provider_in_test_files.call_count == 2
        auditor.config_manager.configure_provider_in_test_files.assert_any_call(
            configurations_dir, auditor.providers[0], auditor.provider_id
        )
        auditor.config_manager.configure_provider_in_test_files.assert_any_call(
            llm_assert_dir, auditor.providers[0], auditor.provider_id
        )

    def test_calls_remove_cloud_only_tests_for_llm_target(self) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        with patch.object(auditor, "_run_redteam_generate_for_configs"):
            auditor.generate_tests_files()

        auditor.config_manager.remove_cloud_only_tests.assert_called_once_with(
            auditor.settings.tests_path / "llm_as_judge_assert"
        )

    def test_does_not_call_remove_cloud_only_tests_for_semantic_fence(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        with patch.object(auditor, "_run_redteam_generate_for_configs"):
            auditor.generate_tests_files()

        auditor.config_manager.remove_cloud_only_tests.assert_not_called()


# ---------------------------------------------------------------------------
# Test Providers & Config Cleaning
# ---------------------------------------------------------------------------


class TestProviders:
    def test_sets_html_provider_correctly(self) -> None:
        auditor = _make_auditor()
        new_config = {"url": "http://new.com", "method": "GET"}
        auditor._set_html_provider(new_config)
        assert auditor.providers[0]["id"] == "http"
        assert auditor.providers[0]["config"] == new_config

    def test_sets_https_provider_id_for_https_url(self) -> None:
        auditor = _make_auditor()
        new_config = {"url": "https://secure.com", "method": "GET"}
        auditor._set_html_provider(new_config)
        assert auditor.providers[0]["config"] == new_config

    def test_retrieves_http_provider_correctly(self) -> None:
        from pentester.auditors.promptfoo.http_provider import PromptfooHTTPProvider

        auditor = _make_auditor()

        # Mix of valid and invalid providers
        auditor.config["providers"] = [
            {"id": "openai", "config": {}},
            {"id": "http", "config": {"url": "http://example.com"}},
        ]

        providers = auditor.get_providers()
        assert len(providers) == 1
        assert isinstance(providers["http"], PromptfooHTTPProvider)

    def test_returns_empty_dict_when_no_http_provider(self) -> None:
        auditor = _make_auditor()
        auditor.config["providers"] = [{"id": "openai", "config": {}}]
        assert auditor.get_providers() == {}


class TestSetProviderFromScanner:
    def test_custom_handler_sets_file_provider_id(self) -> None:
        auditor = _make_auditor()
        scanner = MagicMock()
        scanner.request_handler = MagicMock()
        scanner.custom_handler = "path/to/file.py:MyHandler"

        auditor._set_provider_from_scanner(scanner)

        expected_path = Path("path/to/file.py:MyHandler").resolve().as_posix()
        assert len(auditor.providers) == 1
        assert auditor.providers[0] == {
            "id": f"file://{expected_path}.promptfoo_call_api"
        }
        assert "config" not in auditor.providers[0]

    def test_non_curl_without_custom_handler_leaves_providers_unchanged(self) -> None:
        auditor = _make_auditor()
        original_providers = auditor.providers
        scanner = MagicMock()
        scanner.request_handler = MagicMock()
        scanner.custom_handler = None

        auditor._set_provider_from_scanner(scanner)

        assert auditor.providers is original_providers

    def test_curl_handler_sets_http_provider(self) -> None:
        auditor = _make_auditor()
        scanner = MagicMock()
        handler = MagicMock(spec=CurlHandler)
        parsed = MagicMock(
            url="http://test.com",
            method="POST",
            headers={"Content-Type": "application/json"},
            data='{"text":"$PROMPT"}',
        )
        handler._parse_command.return_value = parsed
        handler.curl_command = "curl http://test.com"
        scanner.request_handler = handler

        auditor._set_provider_from_scanner(scanner)

        assert auditor.providers[0]["id"] == "http"
        assert auditor.providers[0]["config"]["url"] == "http://test.com"
        assert auditor.providers[0]["config"]["method"] == "POST"

    def test_curl_handler_no_providers_skips_setup(self) -> None:
        auditor = _make_auditor()
        auditor.providers = []
        scanner = MagicMock()
        scanner.request_handler = MagicMock(spec=CurlHandler)

        auditor._set_provider_from_scanner(scanner)

        assert auditor.providers == []


class TestConfigureProviderInTestFiles:
    def test_skips_when_no_scanner(self, tmp_path: Path) -> None:
        auditor = _make_auditor()
        auditor._scanner = None

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        (cfg_dir / "test_1.yaml").write_text(
            "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        )

        auditor._configure_provider_in_test_files(cfg_dir)

        auditor.config_manager.configure_provider_in_test_files.assert_not_called()

    def test_skips_when_no_providers(self, tmp_path: Path) -> None:
        auditor = _make_auditor()
        auditor._scanner = MagicMock()
        auditor.providers = []

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        (cfg_dir / "test_1.yaml").write_text(
            "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        )

        auditor._configure_provider_in_test_files(cfg_dir)

        auditor.config_manager.configure_provider_in_test_files.assert_not_called()

    def test_delegates_to_config_manager_when_scanner_and_providers_present(
        self, tmp_path: Path
    ) -> None:
        auditor = _make_auditor()
        auditor._scanner = MagicMock()
        auditor.provider_id = "http"

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()

        auditor._configure_provider_in_test_files(cfg_dir)

        auditor.config_manager.configure_provider_in_test_files.assert_called_once_with(
            cfg_dir, auditor.providers[0], "http"
        )


class TestExtractJsonDotTarget:
    def test_returns_target_from_json_dot_serializer(self) -> None:
        scanner = _make_scanner_with_dot_target("body.data.valid")
        result = PromptfooAuditor._extract_json_dot_target(scanner)
        assert result == "body.data.valid"

    def test_returns_none_when_scanner_is_none(self) -> None:
        assert PromptfooAuditor._extract_json_dot_target(None) is None

    def test_returns_none_when_no_serializer(self) -> None:
        scanner = MagicMock()
        scanner.request_handler.response_serializer = None
        assert PromptfooAuditor._extract_json_dot_target(scanner) is None

    def test_returns_none_when_serializer_is_not_json_dot(self) -> None:
        scanner = MagicMock()
        scanner.request_handler.response_serializer = MagicMock()
        assert PromptfooAuditor._extract_json_dot_target(scanner) is None


# ---------------------------------------------------------------------------
# Test Audit Preparation & Results Processing
# ---------------------------------------------------------------------------


class TestPrepareAuditFiles:
    def test_raises_error_when_no_yaml_files_found(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(output_path=str(tmp_path)), target_type=TargetType.LLM
        )
        (tmp_path / "tests" / "llm_as_judge_assert").mkdir(parents=True, exist_ok=True)

        with pytest.raises(FileNotFoundError):
            auditor._prepare_audit_files()

    def test_prepares_semantic_fence_files(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(output_path=str(tmp_path)),
            target_type=TargetType.SEMANTIC_FENCE,
        )
        llm_dir = tmp_path / "tests" / "llm_as_judge_assert"
        custom_dir = tmp_path / "tests" / "custom_assert"
        llm_dir.mkdir(parents=True, exist_ok=True)
        custom_dir.mkdir(parents=True, exist_ok=True)

        (llm_dir / "test_1.yaml").write_text("data")
        (custom_dir / "test_1.yaml").write_text("cleaned")

        files = auditor._prepare_audit_files()

        auditor.config_manager.clean_config.assert_called_once_with(
            llm_dir / "test_1.yaml", custom_dir
        )
        assert all(str(f).startswith(str(custom_dir)) for f in files)

    def test_configures_provider_in_custom_assert_dir(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(output_path=str(tmp_path)),
            target_type=TargetType.SEMANTIC_FENCE,
        )
        auditor._scanner = MagicMock()
        auditor.provider_id = "http"

        llm_dir = tmp_path / "tests" / "llm_as_judge_assert"
        custom_dir = tmp_path / "tests" / "custom_assert"
        llm_dir.mkdir(parents=True, exist_ok=True)
        custom_dir.mkdir(parents=True, exist_ok=True)

        (llm_dir / "test_1.yaml").write_text("data")
        (custom_dir / "test_1.yaml").write_text("cleaned")

        auditor._prepare_audit_files()

        auditor.config_manager.configure_provider_in_test_files.assert_called_once_with(
            custom_dir, auditor.providers[0], "http"
        )

    def test_prepares_llm_target_files(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(output_path=str(tmp_path)), target_type=TargetType.LLM
        )
        llm_dir = tmp_path / "tests" / "llm_as_judge_assert"
        llm_dir.mkdir(parents=True, exist_ok=True)
        (llm_dir / "test_1.yaml").write_text("data")

        files = auditor._prepare_audit_files()
        assert len(files) == 1
        assert files[0].parent == llm_dir


class TestProcessEvalResults:
    def test_validates_successful_evaluations_only(self) -> None:
        auditor = _make_auditor()
        auditor.collector = MagicMock()
        auditor.config_manager.load_config.return_value = {"tests": [1, 2]}
        results = [
            (Path("/a.yaml"), True, "a.yaml", "ok"),
            (Path("/b.yaml"), False, "b.yaml", "error"),
            (Path("/c.yaml"), True, "c.yaml", "ok"),
        ]

        auditor._process_eval_results(results)

        # Only validates the 2 successful ones. Each yaml loaded had 2 tests.
        assert auditor.collector.validate.call_count == 2
        assert auditor.collector.validate.call_args_list[0][0][2] == 2


# ---------------------------------------------------------------------------
# Test Probe Results Generation
# ---------------------------------------------------------------------------


class TestGenerateProbeResults:
    def _make_results_df(self, **overrides: object) -> pd.DataFrame:
        row: dict = {
            "reason_code": "category_0",
            "prompt": "my_prompt",
            "api_response": {"data": "response_data"},
            "valid": True,
            "accept_score": 0.9,
            "http_status": 200,
            "duration": 1.5,
            "latency_ms": 100,
            "cached": False,
            "strategy_id": "jailbreak-templates",
            "plugin_id": "competitors",
            "error": None,
            "success": True,
            "grading_score": 1.0,
            "grading_reason": "All assertions passed",
        }
        row.update(overrides)
        return pd.DataFrame([row])

    def test_maps_dataframe_rows_to_probe_results_correctly(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df()

        results = auditor._generate_probe_results()

        assert len(results) == 1
        res = results[0]
        assert isinstance(res, ProbeResult)
        assert res.auditor == "promptfoo"
        assert res.attack_category == "jailbreak-templates"
        assert res.attack_type == "competitors"
        assert res.prompt == "my_prompt"
        assert "response_data" in res.response
        assert res.bypassed is False
        assert res.score == 1.0
        assert res.metadata == {
            "http_status": 200,
            "duration": 1.5,
            "latency_ms": 100,
            "cached": False,
            "error": None,
            "grading_reason": "All assertions passed",
            "is_multiturn": False,
        }

    def test_attack_category_defaults_to_basic_when_strategy_id_is_none(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(strategy_id=None)

        results = auditor._generate_probe_results()

        assert results[0].attack_category == "basic"
        assert results[0].attack_type == "competitors"

    def test_returns_empty_list_for_empty_dataframe(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = pd.DataFrame()
        assert auditor._generate_probe_results() == []

    def test_score_defaults_to_zero_when_accept_score_is_none(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(
            grading_score=None, accept_score=None
        )

        results = auditor._generate_probe_results()

        assert results[0].score == 0.0

    def test_error_included_in_metadata(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(error="some error")

        results = auditor._generate_probe_results()

        assert results[0].metadata["error"] == "some error"

    def test_no_error_metadata_is_none(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(error=None)

        results = auditor._generate_probe_results()

        assert results[0].metadata["error"] is None

    def test_bypassed_is_false_when_error_present(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(
            success=False, error="HTTP 422 error"
        )

        results = auditor._generate_probe_results()

        assert results[0].bypassed is False

    def test_bypassed_is_true_when_success_false_and_no_error(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(success=False, error=None)

        results = auditor._generate_probe_results()

        assert results[0].bypassed is True

    def test_bypassed_is_false_when_success_true(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(success=True, error=None)

        results = auditor._generate_probe_results()

        assert results[0].bypassed is False

    def test_prompt_type_is_single(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df()

        results = auditor._generate_probe_results()

        assert results[0].prompt_type == PromptType.SINGLE


# ---------------------------------------------------------------------------
# Test Pre-audit Precondition Validation
# ---------------------------------------------------------------------------


class TestValidatePreconditions:
    @pytest.fixture(autouse=True)
    def _patch_ensure_email(self) -> Generator[None, None, None]:
        with patch.object(PromptfooRunner, "ensure_email_configured"):
            yield

    def test_semantic_fence_passes_when_assert_file_exists(self) -> None:
        auditor = _make_auditor(
            _make_settings(assertion_wrapper_path="/some/assert.py"),
            target_type=TargetType.SEMANTIC_FENCE,
        )
        with patch("pathlib.Path.exists", return_value=True):
            auditor._validate_preconditions()  # should not raise

    def test_semantic_fence_raises_when_assert_file_missing(self) -> None:
        auditor = _make_auditor(
            _make_settings(assertion_wrapper_path="/some/assert.py"),
            target_type=TargetType.SEMANTIC_FENCE,
        )
        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(ValueError, match="Assert file not found"):
                auditor._validate_preconditions()

    def test_semantic_fence_passes_when_wrapper_path_is_none(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        auditor._validate_preconditions()  # should not raise

    def test_llm_passes_when_openai_key_is_set(self) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            auditor._validate_preconditions()  # should not raise

    def test_llm_passes_when_any_known_key_is_set(self) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=True):
            auditor._validate_preconditions()  # should not raise

    def test_llm_raises_when_no_key_is_set(self) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="No LLM API key found"):
                auditor._validate_preconditions()

    def test_semantic_fence_unsets_llm_api_keys(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch.dict(
                os.environ,
                {"OPENAI_API_KEY": "sk-test", "ANTHROPIC_API_KEY": "sk-ant"},
                clear=True,
            ),
        ):
            auditor._unset_llm_api_keys()

            assert "OPENAI_API_KEY" not in os.environ
            assert "ANTHROPIC_API_KEY" not in os.environ
            assert auditor._saved_llm_keys == {
                "OPENAI_API_KEY": "sk-test",
                "ANTHROPIC_API_KEY": "sk-ant",
            }

    def test_semantic_fence_does_not_fail_when_no_keys_present(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch.dict(os.environ, {}, clear=True),
        ):
            auditor._unset_llm_api_keys()
            assert auditor._saved_llm_keys == {}


class TestRestoreLlmApiKeys:
    def test_restores_saved_keys_to_environment(self) -> None:
        auditor = _make_auditor()
        auditor._saved_llm_keys = {"OPENAI_API_KEY": "sk-restored"}

        with patch.dict(os.environ, {}, clear=True):
            auditor._restore_llm_api_keys()

            assert os.environ["OPENAI_API_KEY"] == "sk-restored"
            assert auditor._saved_llm_keys == {}

    def test_noop_when_no_saved_keys(self) -> None:
        auditor = _make_auditor()
        with patch.dict(os.environ, {}, clear=True):
            auditor._restore_llm_api_keys()  # should not raise
            assert auditor._saved_llm_keys == {}


# ---------------------------------------------------------------------------
# Test Audit Pipeline orchestration
# ---------------------------------------------------------------------------


class TestAudit:
    def test_executes_full_audit_pipeline(self) -> None:
        auditor = _make_auditor()
        files = [Path("/a.yaml")]
        runner_output = [(Path("/a.yaml"), True, "a.yaml", "ok")]
        expected_df = pd.DataFrame({"col": [1]})
        expected_probes = [MagicMock(spec=ProbeResult)]

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files") as mock_gen,
            patch.object(auditor.collector, "clean") as mock_clean,
            patch.object(
                auditor, "_prepare_audit_files", return_value=files
            ) as mock_prep,
            patch.object(
                auditor.runner, "run_all", return_value=runner_output
            ) as mock_run,
            patch.object(auditor, "_process_eval_results") as mock_proc,
            patch.object(
                auditor.collector, "build_dataframe", return_value=expected_df
            ) as mock_build,
            patch.object(
                auditor, "_generate_probe_results", return_value=expected_probes
            ) as mock_gen_probes,
        ):
            result, _ = auditor.audit()

        mock_gen.assert_called_once()
        mock_clean.assert_called_once()
        mock_prep.assert_called_once()
        mock_run.assert_called_once_with(files)
        mock_proc.assert_called_once_with(runner_output)
        mock_build.assert_called_once()
        mock_gen_probes.assert_called_once()

        assert auditor.results_df is expected_df
        assert result is expected_probes

    def test_returns_empty_list_when_no_results(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(auditor, "_prepare_audit_files", return_value=[]),
            patch.object(auditor.runner, "run_all", return_value=[]),
            patch.object(auditor, "_process_eval_results"),
            patch.object(
                auditor.collector, "build_dataframe", return_value=pd.DataFrame()
            ),
            patch.object(auditor, "_generate_probe_results", return_value=[]),
        ):
            result, _ = auditor.audit()
            assert result == []

    def test_builds_dataframe_and_logs_errors_when_all_evals_failed(self) -> None:
        auditor = _make_auditor()
        all_failed = [
            (Path("/a.yaml"), False, "a.yaml", "error A"),
            (Path("/b.yaml"), False, "b.yaml", "error B"),
        ]
        expected_df = pd.DataFrame({"col": [1]})
        error_probe = MagicMock(spec=ProbeResult)
        error_probe.is_error = True
        error_probe.attack_category = "cat"
        error_probe.attack_type = "type"
        error_probe.metadata = {"error": "something went wrong"}

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(
                auditor,
                "_prepare_audit_files",
                return_value=[Path("/a.yaml"), Path("/b.yaml")],
            ),
            patch.object(auditor.runner, "run_all", return_value=all_failed),
            patch.object(auditor, "_process_eval_results"),
            patch.object(
                auditor.collector, "build_dataframe", return_value=expected_df
            ) as mock_build,
            patch.object(
                auditor, "_generate_probe_results", return_value=[error_probe]
            ) as mock_gen_probes,
            patch("pentester.auditors.promptfoo.auditor.logger") as mock_logger,
        ):
            result, _ = auditor.audit()

        assert mock_build.call_count == 1
        assert mock_gen_probes.call_count == 2
        mock_logger.error.assert_called_once_with(
            "Probe error — category: %s | type: %s | error: %s",
            "cat",
            "type",
            "something went wrong",
        )
        assert result == [error_probe]
        assert auditor.results_df is expected_df

    def test_no_error_logs_when_all_evals_failed_but_no_error_probes(self) -> None:
        auditor = _make_auditor()
        all_failed = [
            (Path("/a.yaml"), False, "a.yaml", "error A"),
        ]
        non_error_probe = MagicMock(spec=ProbeResult)
        non_error_probe.is_error = False

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(
                auditor, "_prepare_audit_files", return_value=[Path("/a.yaml")]
            ),
            patch.object(auditor.runner, "run_all", return_value=all_failed),
            patch.object(auditor, "_process_eval_results"),
            patch.object(
                auditor.collector, "build_dataframe", return_value=pd.DataFrame()
            ),
            patch.object(
                auditor, "_generate_probe_results", return_value=[non_error_probe]
            ),
            patch("pentester.auditors.promptfoo.auditor.logger") as mock_logger,
        ):
            result, _ = auditor.audit()

        mock_logger.error.assert_not_called()
        assert result == [non_error_probe]

    def test_calls_build_dataframe_when_at_least_one_eval_succeeded(self) -> None:
        auditor = _make_auditor()
        mixed_results = [
            (Path("/a.yaml"), True, "a.yaml", "ok"),
            (Path("/b.yaml"), False, "b.yaml", "error B"),
        ]
        expected_df = pd.DataFrame({"col": [1]})
        expected_probes = [MagicMock(spec=ProbeResult)]

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(
                auditor,
                "_prepare_audit_files",
                return_value=[Path("/a.yaml"), Path("/b.yaml")],
            ),
            patch.object(auditor.runner, "run_all", return_value=mixed_results),
            patch.object(auditor, "_process_eval_results"),
            patch.object(
                auditor.collector, "build_dataframe", return_value=expected_df
            ) as mock_build,
            patch.object(
                auditor, "_generate_probe_results", return_value=expected_probes
            ),
        ):
            result, _ = auditor.audit()

        mock_build.assert_called_once()
        assert result is expected_probes


# ---------------------------------------------------------------------------
# Multi-turn Strategy Tests
# ---------------------------------------------------------------------------


class TestSplitAuditFiles:
    def test_splits_by_prefix(self) -> None:
        files = [
            Path("/test_1.yaml"),
            Path("/multiturn_test_1.yaml"),
            Path("/test_2.yaml"),
            Path("/multiturn_test_2.yaml"),
        ]
        single, multi = PromptfooAuditor._split_audit_files(files)
        assert len(single) == 2
        assert len(multi) == 2
        assert all(not f.name.startswith("multiturn_") for f in single)
        assert all(f.name.startswith("multiturn_") for f in multi)

    def test_returns_empty_lists_when_no_files(self) -> None:
        single, multi = PromptfooAuditor._split_audit_files([])
        assert single == []
        assert multi == []

    def test_all_single_turn(self) -> None:
        files = [Path("/test_1.yaml"), Path("/test_2.yaml")]
        single, multi = PromptfooAuditor._split_audit_files(files)
        assert len(single) == 2
        assert len(multi) == 0
