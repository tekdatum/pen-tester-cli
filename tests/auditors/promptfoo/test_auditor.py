from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, mock_open, patch

import pandas as pd
import pytest

from pentester.auditors.models.probe_result import ProbeResult
from pentester.auditors.promptfoo.auditor import PromptfooAuditor
from pentester.config.auditors.promptfoo_settings import PromptfooSettings
from pentester.config.settings import TargetType


_FAKE_CONFIG: dict[str, Any] = {
    "prompts": ["You are a helpful assistant"],
    "providers": [
        {"id": "http", "config": {"url": "http://example.com", "method": "POST"}}
    ],
    "redteam": {
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


def _make_auditor(
    settings: PromptfooSettings | None = None,
    scanner: object = None,
    target_type: TargetType = TargetType.SEMANTIC_FENCE,
) -> PromptfooAuditor:
    s = settings or _make_settings()
    with (
        patch("pathlib.Path.mkdir"),
        patch("builtins.open", mock_open(read_data="")),
        patch("pentester.auditors.promptfoo.auditor.yaml.safe_load", return_value=copy.deepcopy(_FAKE_CONFIG)),
    ):
        return PromptfooAuditor(settings=s, scanner=scanner, target_type=target_type)

# ---------------------------------------------------------------------------
# TestInit & TestEnsureDirectories
# ---------------------------------------------------------------------------

class TestInit:
    def test_initializes_with_explicit_settings(self) -> None:
        s = _make_settings(config_path="/custom", files_parallel=7, internal_concurrency=3)
        auditor = _make_auditor(s)
        
        assert auditor.settings is s
        assert auditor.runner.results_path == Path("./output/promptfoo") / "results"
        assert auditor.runner.files_parallel == 7
        assert auditor.runner.concurrency == 3
        assert auditor.collector.results_path == Path("./output/promptfoo") / "results"
        assert isinstance(auditor.results_df, pd.DataFrame)
        assert len(auditor.results_df) == 0

    def test_initializes_with_default_settings_when_none_provided(self) -> None:
        with (
            patch("pathlib.Path.mkdir"),
            patch("builtins.open", mock_open(read_data="")),
            patch("pentester.auditors.promptfoo.auditor.yaml.safe_load", return_value=copy.deepcopy(_FAKE_CONFIG)),
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
        with (
            patch("pathlib.Path.mkdir") as mock_mkdir,
            patch("builtins.open", mock_open(read_data="")),
            patch("pentester.auditors.promptfoo.auditor.yaml.safe_load", return_value=copy.deepcopy(_FAKE_CONFIG)),
        ):
            PromptfooAuditor(settings=_make_settings())
            
        assert mock_mkdir.call_count == 4
        for call_obj in mock_mkdir.call_args_list:
            assert call_obj[1].get("parents") is True
            assert call_obj[1].get("exist_ok") is True

class TestLoadConfig:
    def test_extracts_all_expected_fields_from_yaml(self) -> None:
        auditor = _make_auditor()
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch("pentester.auditors.promptfoo.auditor.yaml.safe_load", return_value=copy.deepcopy(_FAKE_CONFIG)),
        ):
            config = auditor._load_config(Path("/fake.yaml"))
            
        expected_keys = {"prompts", "providers", "redteam", "defaultTest", "tests", "commandLineOptions", "metadata"}
        assert set(config.keys()) == expected_keys
        assert config["prompts"] == _FAKE_CONFIG["prompts"]
        assert config["providers"] == _FAKE_CONFIG["providers"]
        assert config["metadata"] == {"version": "1.0"}

    def test_applies_defaults_for_missing_fields(self) -> None:
        auditor = _make_auditor()
        minimal_config = {"prompts": ["p"]}  # Missing providers and metadata, prompts supplied
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch("pentester.auditors.promptfoo.auditor.yaml.safe_load", return_value=minimal_config),
        ):
            config = auditor._load_config(Path("/fake.yaml"))
            
        assert config["providers"] is None
        assert config["metadata"] == {}
        
        # Test missing prompts specifically
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch("pentester.auditors.promptfoo.auditor.yaml.safe_load", return_value={"providers": None}),
        ):
            empty_prompts_config = auditor._load_config(Path("/fake.yaml"))
            assert empty_prompts_config["prompts"] == []


class TestOpenConfig:
    def test_sets_all_config_attributes(self) -> None:
        # _open_config is implicitly called during _make_auditor init
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

class TestWritePluginConfigs:
    def test_writes_new_configs_with_correct_formatting(self, tmp_path: Path) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor._write_plugin_configs(["harmful:hate", "harmful:xss"], configs_dir)

        assert mock_dump.call_count == 2
        first_config = mock_dump.call_args_list[0][0][0]
        second_config = mock_dump.call_args_list[1][0][0]

        assert "metadata" not in first_config
        assert first_config["redteam"]["plugins"] == ["harmful:hate"]
        assert "defaultAssertions" not in first_config["redteam"]
        assert second_config["redteam"]["plugins"] == ["harmful:xss"]
        assert (configs_dir / "test_1.yaml").exists()
        assert (configs_dir / "test_2.yaml").exists()
        assert "defaultAssertions" in auditor.config["redteam"]  # original unchanged

    def test_handles_existing_files_based_on_replace_setting(self, tmp_path: Path) -> None:
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        existing_file = configs_dir / "test_1.yaml"
        
        # Test replace = False
        s_no_replace = _make_settings(replace_existing_file=False)
        existing_file.write_text("existing")
        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            _make_auditor(s_no_replace)._write_plugin_configs(["harmful:hate"], configs_dir)
            mock_dump.assert_not_called()

        # Test replace = True
        s_replace = _make_settings(replace_existing_file=True)
        existing_file.write_text("old data")
        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            _make_auditor(s_replace)._write_plugin_configs(["harmful:hate"], configs_dir)
            mock_dump.assert_called()


class TestRunRedteamGenerateForConfigs:
    def test_calls_runner_for_all_configs_handling_replace_setting(self, tmp_path: Path) -> None:
        configs_dir = tmp_path / "configurations"
        llm_dir = tmp_path / "llm_assert"
        configs_dir.mkdir()
        llm_dir.mkdir()
        
        (configs_dir / "test_1.yaml").write_text("data")
        (configs_dir / "test_2.yaml").write_text("data")
        
        # Setup auditor
        auditor = _make_auditor(_make_settings(replace_existing_file=False))
        auditor.runner = MagicMock()
        
        # If replace is false and output exists, it should skip. Let's make test_1 exist.
        (llm_dir / "test_1.yaml").write_text("existing output")
        
        auditor._run_redteam_generate_for_configs(configs_dir, llm_dir)
        
        # test_1 was skipped, test_2 was generated
        assert auditor.runner.run_redteam_generate.call_count == 1
        call_args = auditor.runner.run_redteam_generate.call_args
        assert call_args[0][1] == llm_dir / "test_2.yaml"


class TestGenerateTestsFiles:
    def test_orchestrates_plugin_writing_and_generation(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_write_plugin_configs") as mock_write,
            patch.object(auditor, "_run_redteam_generate_for_configs") as mock_gen,
        ):
            auditor.generate_tests_files()
            
        mock_write.assert_called_once()
        assert mock_write.call_args[0][0] == _FAKE_CONFIG["redteam"]["plugins"]
        mock_gen.assert_called_once()

# ---------------------------------------------------------------------------
# Test Providers & Config Cleaning
# ---------------------------------------------------------------------------

class TestProviders:
    def test_sets_html_provider_correctly(self) -> None:
        auditor = _make_auditor()
        new_config = {"url": "http://new.com", "method": "GET"}
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


class TestCleanConfig:
    def test_raises_error_for_llm_target_type(self, tmp_path: Path) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        with pytest.raises(Exception, match="not allowed"):
            auditor.clean_config(Path("/test.yaml"), tmp_path / "output")

    def test_cleans_and_writes_config_correctly(self, tmp_path: Path) -> None:
        auditor = _make_auditor(_make_settings(assertion_wrapper_path="/my/assert.py"))
        output = tmp_path / "output"
        
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch("pentester.auditors.promptfoo.auditor.yaml.safe_load", return_value=copy.deepcopy(_FAKE_CONFIG)),
            patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump,
        ):
            auditor.clean_config(Path("/test.yaml"), output)
            
        assert output.exists()
        written = mock_dump.call_args[0][0]
        for test in written["tests"]:
            assert test["assert"][0]["type"] == "python"
            assert "/my/assert.py" in test["assert"][0]["value"]

    def test_handles_existing_files_based_on_replace_setting(self, tmp_path: Path) -> None:
        output = tmp_path / "output"
        output.mkdir()
        (output / "test.yaml").write_text("old")
        
        # Test replace = False
        auditor_no_replace = _make_auditor(_make_settings(replace_existing_file=False))
        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor_no_replace.clean_config(Path("/test.yaml"), output)
            mock_dump.assert_not_called()

# ---------------------------------------------------------------------------
# Test Audit Preparation & Results Processing
# ---------------------------------------------------------------------------

class TestPrepareAuditFiles:
    def test_raises_error_when_no_yaml_files_found(self, tmp_path: Path) -> None:
        auditor = _make_auditor(_make_settings(output_path=str(tmp_path)), target_type=TargetType.LLM)
        (tmp_path / "tests" / "llm_as_judge_assert").mkdir(parents=True, exist_ok=True)

        with pytest.raises(FileNotFoundError):
            auditor._prepare_audit_files()

    def test_prepares_semantic_fence_files(self, tmp_path: Path) -> None:
        auditor = _make_auditor(_make_settings(output_path=str(tmp_path)), target_type=TargetType.SEMANTIC_FENCE)
        llm_dir = tmp_path / "tests" / "llm_as_judge_assert"
        custom_dir = tmp_path / "tests" / "custom_assert"
        llm_dir.mkdir(parents=True, exist_ok=True)
        custom_dir.mkdir(parents=True, exist_ok=True)

        (llm_dir / "test_1.yaml").write_text("data")
        (custom_dir / "test_1.yaml").write_text("cleaned")

        with patch.object(auditor, "clean_config") as mock_clean:
            files = auditor._prepare_audit_files()

        mock_clean.assert_called_once()
        assert all(str(f).startswith(str(custom_dir)) for f in files)

    def test_prepares_llm_target_files(self, tmp_path: Path) -> None:
        auditor = _make_auditor(_make_settings(output_path=str(tmp_path)), target_type=TargetType.LLM)
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
        results = [
            (Path("/a.yaml"), True, "a.yaml", "ok"),
            (Path("/b.yaml"), False, "b.yaml", "error"),
            (Path("/c.yaml"), True, "c.yaml", "ok"),
        ]
        
        with patch.object(auditor, "_load_config", return_value={"tests": [1, 2]}):
            auditor._process_eval_results(results)
            
        # Only validates the 2 successful ones. Each yaml loaded had 2 tests.
        assert auditor.collector.validate.call_count == 2
        assert auditor.collector.validate.call_args_list[0][0][2] == 2  # Checks test count is passed

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
        assert res.auditor == "PromptfooAuditor"
        assert res.attack_category == "jailbreak-templates"
        assert res.attack_type == "competitors"
        assert res.prompt == "my_prompt"
        assert "response_data" in res.response
        assert res.bypassed is True
        assert res.score == 0.9
        assert res.metadata == {
            "http_status": 200,
            "duration": 1.5,
            "latency_ms": 100,
            "cached": False,
            "error": None,
        }

    def test_returns_empty_list_for_empty_dataframe(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = pd.DataFrame()
        assert auditor._generate_probe_results() == []

    def test_score_defaults_to_zero_when_accept_score_is_none(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(accept_score=None)

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

# ---------------------------------------------------------------------------
# Test Pre-audit Precondition Validation
# ---------------------------------------------------------------------------

class TestValidatePreconditions:
    def test_semantic_fence_passes_when_assert_file_exists(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        with patch("pathlib.Path.exists", return_value=True):
            auditor._validate_preconditions()  # should not raise

    def test_semantic_fence_raises_when_assert_file_missing(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(ValueError, match="Assert file not found"):
                auditor._validate_preconditions()

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
            patch.object(auditor, "_prepare_audit_files", return_value=files) as mock_prep,
            patch.object(auditor.runner, "run_all", return_value=runner_output) as mock_run,
            patch.object(auditor, "_process_eval_results") as mock_proc,
            patch.object(auditor.collector, "build_dataframe", return_value=expected_df) as mock_build,
            patch.object(auditor, "_generate_probe_results", return_value=expected_probes) as mock_gen_probes,
        ):
            result = auditor.audit()
            
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
            patch.object(auditor.collector, "build_dataframe", return_value=pd.DataFrame()),
            patch.object(auditor, "_generate_probe_results", return_value=[]),
        ):
            assert auditor.audit() == []

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
            patch.object(auditor, "_prepare_audit_files", return_value=[Path("/a.yaml"), Path("/b.yaml")]),
            patch.object(auditor.runner, "run_all", return_value=all_failed),
            patch.object(auditor, "_process_eval_results"),
            patch.object(auditor.collector, "build_dataframe", return_value=expected_df) as mock_build,
            patch.object(auditor, "_generate_probe_results", return_value=[error_probe]) as mock_gen_probes,
            patch("pentester.auditors.promptfoo.auditor.logger") as mock_logger,
        ):
            result = auditor.audit()

        mock_build.assert_called_once()
        mock_gen_probes.assert_called_once()
        mock_logger.error.assert_called_once_with(
            "Probe error — category: %s | type: %s | error: %s",
            "cat",
            "type",
            "something went wrong",
        )
        assert result == []
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
            patch.object(auditor, "_prepare_audit_files", return_value=[Path("/a.yaml")]),
            patch.object(auditor.runner, "run_all", return_value=all_failed),
            patch.object(auditor, "_process_eval_results"),
            patch.object(auditor.collector, "build_dataframe", return_value=pd.DataFrame()),
            patch.object(auditor, "_generate_probe_results", return_value=[non_error_probe]),
            patch("pentester.auditors.promptfoo.auditor.logger") as mock_logger,
        ):
            result = auditor.audit()

        mock_logger.error.assert_not_called()
        assert result == []

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
            patch.object(auditor, "_prepare_audit_files", return_value=[Path("/a.yaml"), Path("/b.yaml")]),
            patch.object(auditor.runner, "run_all", return_value=mixed_results),
            patch.object(auditor, "_process_eval_results"),
            patch.object(auditor.collector, "build_dataframe", return_value=expected_df) as mock_build,
            patch.object(auditor, "_generate_probe_results", return_value=expected_probes),
        ):
            result = auditor.audit()

        mock_build.assert_called_once()
        assert result is expected_probes
