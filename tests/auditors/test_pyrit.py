"""Tests for pentester.auditors.pyrit.PyritProbe.

Design notes
------------
* pyrit is an external library not in requirements.txt. All pyrit.* modules are
  stubbed via sys.modules before the module under test is imported so the suite
  runs without the real package present.
* initialize_pyrit_async is set to AsyncMock at stub-setup time so the binding
  inside pyrit.py resolves correctly on import.
* SeedDatasetProvider.fetch_datasets_async is set to AsyncMock in each fixture
  since it is accessed as an attribute (not imported directly).
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Register sys.modules stubs BEFORE importing the module under test.
# ---------------------------------------------------------------------------

_pyrit_mod = MagicMock(name="pyrit")
_pyrit_datasets_mod = MagicMock(name="pyrit.datasets")
_pyrit_setup_mod = MagicMock(name="pyrit.setup")


class _FakePromptChatTarget:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def get_identifier(self) -> dict:
        return {}


_pyrit_prompt_target_mod = MagicMock(name="pyrit.prompt_target")
_pyrit_prompt_target_mod.OpenAIChatTarget = MagicMock(name="OpenAIChatTarget")
_pyrit_prompt_target_mod.PromptChatTarget = _FakePromptChatTarget
_pyrit_score_mod = MagicMock(name="pyrit.score")
_pyrit_score_tf_mod = MagicMock(name="pyrit.score.true_false")
_pyrit_score_tf_scorer_mod = MagicMock(
    name="pyrit.score.true_false.self_ask_true_false_scorer"
)
_pyrit_models_mod = MagicMock(name="pyrit.models")
_tqdm_mod = MagicMock(name="tqdm")
_tqdm_mod.tqdm = lambda iterable, **_kwargs: iterable

# initialize_pyrit_async is imported directly into pyrit.py; set it to
# AsyncMock now so the binding is correct when the module is first imported.
_pyrit_setup_mod.initialize_pyrit_async = AsyncMock()

for _name, _stub in [
    ("pyrit", _pyrit_mod),
    ("pyrit.datasets", _pyrit_datasets_mod),
    ("pyrit.executor", MagicMock(name="pyrit.executor")),
    ("pyrit.executor.attack", MagicMock(name="pyrit.executor.attack")),
    ("pyrit.executor.attack.core", MagicMock(name="pyrit.executor.attack.core")),
    (
        "pyrit.executor.attack.multi_turn",
        MagicMock(name="pyrit.executor.attack.multi_turn"),
    ),
    ("pyrit.memory", MagicMock(name="pyrit.memory")),
    ("pyrit.setup", _pyrit_setup_mod),
    ("pyrit.prompt_target", _pyrit_prompt_target_mod),
    ("pyrit.score", _pyrit_score_mod),
    ("pyrit.score.true_false", _pyrit_score_tf_mod),
    ("pyrit.score.true_false.self_ask_true_false_scorer", _pyrit_score_tf_scorer_mod),
    ("pyrit.models", _pyrit_models_mod),
    ("pyrit.models.attack_result", MagicMock(name="pyrit.models.attack_result")),
    ("tqdm", _tqdm_mod),
]:
    sys.modules.setdefault(_name, _stub)

# Re-read from sys.modules so local variables always reference the registered stubs.
_pyrit_datasets_mod = sys.modules["pyrit.datasets"]
_pyrit_setup_mod = sys.modules["pyrit.setup"]
_pyrit_prompt_target_mod = sys.modules["pyrit.prompt_target"]
_pyrit_score_mod = sys.modules["pyrit.score"]
_pyrit_score_tf_scorer_mod = sys.modules[
    "pyrit.score.true_false.self_ask_true_false_scorer"
]
_pyrit_models_mod = sys.modules["pyrit.models"]

from pentester.auditors.pyrit.auditor import PyritAuditor as PyritProbe  # noqa: E402
from pentester.auditors.pyrit.scanner_target import ScannerTarget  # noqa: E402
from pentester.auditors.models.probe_result import ProbeResult  # noqa: E402
from pentester.config.auditors.pyrit_settings import PyritSettings  # noqa: E402
from pentester.config.llm import LLMProvider, LLMSettings  # noqa: E402
from pentester.config.settings import TargetType, clear_settings_cache  # noqa: E402
from pentester.enums.auditor_key import AuditorKey  # noqa: E402
from pentester.scanners.scanner import Scanner  # noqa: E402


@pytest.fixture(autouse=True)
def reset_cache() -> None:  # type: ignore[return]
    clear_settings_cache()
    yield
    clear_settings_cache()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auditor(
    settings: PyritSettings | None = None,
    llm_settings: LLMSettings | None = None,
) -> PyritProbe:
    return PyritProbe(
        settings=settings or PyritSettings(),
        llm_settings=llm_settings or LLMSettings(),
    )


def _make_llm_auditor(
    settings: PyritSettings | None = None,
    llm_settings: LLMSettings | None = None,
) -> PyritProbe:
    auditor = _make_auditor(settings, llm_settings)
    auditor.target_type = TargetType.LLM
    return auditor


def _make_seed(
    value: str = "inject prompt", harm_categories: list[str] | None = None
) -> MagicMock:
    seed = MagicMock()
    seed.value = value
    seed.harm_categories = harm_categories or ["violence"]
    return seed


def _make_dataset(name: str = "test_dataset", seeds: list | None = None) -> MagicMock:
    dataset = MagicMock()
    dataset.dataset_name = name
    dataset.seeds = seeds if seeds is not None else [_make_seed()]
    return dataset


def _make_scan_result(
    response: str = "HTTP/1.1 200 OK\n\n{}",
    bypassed: bool = True,
    score: float = 0.9,
) -> MagicMock:
    result = MagicMock()
    result.response = response
    result.bypassed = bypassed
    result.score = score
    return result


def _make_llm_response(text: str = "LLM output") -> MagicMock:
    response = MagicMock()
    response.get_value.return_value = text
    return response


def _make_score(value: bool = True) -> MagicMock:
    score = MagicMock()
    score.get_value.return_value = value
    return score


# ---------------------------------------------------------------------------
# _init_target
# ---------------------------------------------------------------------------


class TestInitTarget:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        _pyrit_prompt_target_mod.OpenAIChatTarget.reset_mock()

    def test_openai_passes_openai_endpoint(self) -> None:
        _make_auditor(
            llm_settings=LLMSettings(model="gpt-4o", provider=LLMProvider.OPENAI)
        )._init_target()
        _pyrit_prompt_target_mod.OpenAIChatTarget.assert_called_once_with(
            model_name="gpt-4o",
            endpoint="https://api.openai.com/v1",
            is_json_supported=True,
        )

    def test_openai_passes_endpoint(self) -> None:
        _make_auditor(
            llm_settings=LLMSettings(model="gpt-4o", provider=LLMProvider.OPENAI)
        )._init_target()
        assert "endpoint" in _pyrit_prompt_target_mod.OpenAIChatTarget.call_args.kwargs

    def test_anthropic_passes_anthropic_endpoint(self) -> None:
        _make_auditor(
            llm_settings=LLMSettings(
                model="claude-3-5-sonnet", provider=LLMProvider.ANTHROPIC
            )
        )._init_target()
        _pyrit_prompt_target_mod.OpenAIChatTarget.assert_called_once_with(
            model_name="claude-3-5-sonnet",
            endpoint="https://api.anthropic.com/v1",
            is_json_supported=True,
        )

    def test_gemini_passes_gemini_endpoint(self) -> None:
        _make_auditor(
            llm_settings=LLMSettings(
                model="gemini-1.5-pro", provider=LLMProvider.GEMINI
            )
        )._init_target()
        _pyrit_prompt_target_mod.OpenAIChatTarget.assert_called_once_with(
            model_name="gemini-1.5-pro",
            endpoint="https://generativelanguage.googleapis.com/v1beta/openai/",
            is_json_supported=True,
        )

    def test_returns_openai_chat_target(self) -> None:
        result = _make_auditor(llm_settings=LLMSettings(model="gpt-4o"))._init_target()
        assert result is _pyrit_prompt_target_mod.OpenAIChatTarget.return_value


# ---------------------------------------------------------------------------
# _init_scorer
# ---------------------------------------------------------------------------


class TestInitScorer:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        _pyrit_prompt_target_mod.OpenAIChatTarget.reset_mock()
        _pyrit_score_mod.SelfAskTrueFalseScorer.reset_mock()

    def test_creates_scorer_target_with_llm_model(self) -> None:
        _make_auditor(llm_settings=LLMSettings(model="gpt-4o"))._init_scorer()
        _pyrit_prompt_target_mod.OpenAIChatTarget.assert_called_once_with(
            model_name="gpt-4o",
            endpoint="https://api.openai.com/v1",
            is_json_supported=True,
        )

    def test_scorer_passes_anthropic_endpoint_when_provider_anthropic(self) -> None:
        _make_auditor(
            llm_settings=LLMSettings(
                model="claude-3-5-haiku", provider=LLMProvider.ANTHROPIC
            )
        )._init_scorer()
        _pyrit_prompt_target_mod.OpenAIChatTarget.assert_called_once_with(
            model_name="claude-3-5-haiku",
            endpoint="https://api.anthropic.com/v1",
            is_json_supported=False,
        )

    def test_scorer_passes_gemini_endpoint_when_provider_gemini(self) -> None:
        _make_auditor(
            llm_settings=LLMSettings(
                model="gemini-1.5-flash", provider=LLMProvider.GEMINI
            )
        )._init_scorer()
        _pyrit_prompt_target_mod.OpenAIChatTarget.assert_called_once_with(
            model_name="gemini-1.5-flash",
            endpoint="https://generativelanguage.googleapis.com/v1beta/openai/",
            is_json_supported=True,
        )

    def test_anthropic_scorer_disables_json_response(self) -> None:
        _make_auditor(
            llm_settings=LLMSettings(
                model="claude-3-5-haiku", provider=LLMProvider.ANTHROPIC
            )
        )._init_scorer()
        call_kwargs = _pyrit_prompt_target_mod.OpenAIChatTarget.call_args.kwargs
        assert call_kwargs["is_json_supported"] is False

    def test_non_anthropic_scorer_keeps_json_response_enabled(self) -> None:
        _make_auditor(
            llm_settings=LLMSettings(model="gpt-4o", provider=LLMProvider.OPENAI)
        )._init_scorer()
        call_kwargs = _pyrit_prompt_target_mod.OpenAIChatTarget.call_args.kwargs
        assert call_kwargs["is_json_supported"] is True

    def test_passes_scorer_target_to_self_ask_scorer(self) -> None:
        scorer_target = MagicMock()
        _pyrit_prompt_target_mod.OpenAIChatTarget.return_value = scorer_target
        _make_auditor(llm_settings=LLMSettings(model="gpt-4o"))._init_scorer()
        call_kwargs = _pyrit_score_mod.SelfAskTrueFalseScorer.call_args.kwargs
        assert call_kwargs["chat_target"] is scorer_target

    def test_passes_question_to_self_ask_scorer(self) -> None:
        mock_question = MagicMock()
        _pyrit_score_tf_scorer_mod.TrueFalseQuestion.return_value = mock_question
        _make_auditor(llm_settings=LLMSettings(model="gpt-4o"))._init_scorer()
        call_kwargs = _pyrit_score_mod.SelfAskTrueFalseScorer.call_args.kwargs
        assert call_kwargs["true_false_question"] is mock_question

    def test_returns_self_ask_scorer(self) -> None:
        result = _make_auditor(llm_settings=LLMSettings(model="gpt-4o"))._init_scorer()
        assert result is _pyrit_score_mod.SelfAskTrueFalseScorer.return_value


# ---------------------------------------------------------------------------
# _init_scanner
# ---------------------------------------------------------------------------


class TestInitScanner:
    def test_returns_scanner_instance(self) -> None:
        assert isinstance(_make_auditor()._init_scanner(), Scanner)


# ---------------------------------------------------------------------------
# audit — dataset loading (shared between both target types)
# ---------------------------------------------------------------------------


class TestLoadDatasets:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        _pyrit_setup_mod.initialize_pyrit_async.reset_mock()
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async = AsyncMock(
            return_value=[]
        )
        _pyrit_datasets_mod.SeedDatasetProvider.get_all_dataset_names.return_value = []

    def _run(self, settings: PyritSettings) -> list[ProbeResult]:
        auditor = _make_auditor(settings)
        with (
            patch.object(auditor, "_init_scanner", return_value=MagicMock()),
        ):
            return auditor.audit()

    def test_uses_settings_dataset_names_when_set(self) -> None:
        self._run(PyritSettings(dataset_names=["xstest"]))
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async.assert_called_once_with(
            dataset_names=["xstest"]
        )

    def test_uses_all_dataset_names_when_settings_empty(self) -> None:
        _pyrit_datasets_mod.SeedDatasetProvider.get_all_dataset_names.return_value = [
            "a",
            "b",
        ]
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async = AsyncMock(
            return_value=[]
        )
        self._run(PyritSettings(dataset_names=[]))
        assert (
            _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async.call_count == 2
        )

    def test_skips_failed_dataset_and_logs_warning(self) -> None:
        _pyrit_datasets_mod.SeedDatasetProvider.get_all_dataset_names.return_value = [
            "bad",
            "good",
        ]
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async = AsyncMock(
            side_effect=[RuntimeError("gated"), []]
        )
        with patch("pentester.auditors.pyrit.auditor.logger") as mock_logger:
            self._run(PyritSettings(dataset_names=[]))
        mock_logger.warning.assert_called_once()

    def test_applies_max_seeds_limit(self) -> None:
        seeds = [_make_seed(f"p{i}") for i in range(5)]
        dataset = _make_dataset(seeds=seeds)
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async = AsyncMock(
            return_value=[dataset]
        )
        scanner = MagicMock()
        scanner.scan.return_value = _make_scan_result()
        auditor = _make_auditor(PyritSettings(dataset_names=["x"], max_seeds=2))
        with patch.object(auditor, "_init_scanner", return_value=scanner):
            results = auditor.audit()
        assert len(results) == 2

    def test_no_limit_when_max_seeds_none(self) -> None:
        seeds = [_make_seed(f"p{i}") for i in range(4)]
        dataset = _make_dataset(seeds=seeds)
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async = AsyncMock(
            return_value=[dataset]
        )
        scanner = MagicMock()
        scanner.scan.return_value = _make_scan_result()
        auditor = _make_auditor(PyritSettings(dataset_names=["x"], max_seeds=None))
        with patch.object(auditor, "_init_scanner", return_value=scanner):
            results = auditor.audit()
        assert len(results) == 4


# ---------------------------------------------------------------------------
# audit — SEMANTIC_FENCE path
# ---------------------------------------------------------------------------


class TestAuditSemanticFence:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        _pyrit_setup_mod.initialize_pyrit_async.reset_mock()
        self.mock_scanner = MagicMock()
        self.mock_scanner.scan.return_value = _make_scan_result()

    def _audit_with(
        self, seeds: list, scanner: MagicMock | None = None
    ) -> list[ProbeResult]:
        dataset = _make_dataset(seeds=seeds)
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async = AsyncMock(
            return_value=[dataset]
        )
        auditor = _make_auditor(PyritSettings(dataset_names=["x"]))
        with patch.object(
            auditor, "_init_scanner", return_value=scanner or self.mock_scanner
        ):
            return auditor.audit()

    def test_returns_one_result_per_seed(self) -> None:
        assert len(self._audit_with([_make_seed(), _make_seed()])) == 2

    def test_scanner_called_with_each_prompt(self) -> None:
        self._audit_with([_make_seed("first"), _make_seed("second")])
        calls = [c.args[0] for c in self.mock_scanner.scan.call_args_list]
        assert calls == ["first", "second"]

    def test_result_auditor_is_pyrit(self) -> None:
        results = self._audit_with([_make_seed()])
        assert results[0].auditor == "pyrit"

    def test_result_prompt_from_seed(self) -> None:
        results = self._audit_with([_make_seed("my prompt")])
        assert results[0].prompt == "my prompt"

    def test_result_attack_category_from_harm_categories(self) -> None:
        results = self._audit_with([_make_seed(harm_categories=["violence", "hate"])])
        assert results[0].attack_category == "violence,hate"

    def test_result_attack_type_is_default(self) -> None:
        results = self._audit_with([_make_seed()])
        assert results[0].attack_type == "default"

    def test_result_response_from_scanner(self) -> None:
        self.mock_scanner.scan.return_value = _make_scan_result(response="raw response")
        results = self._audit_with([_make_seed()])
        assert results[0].response == "raw response"

    def test_result_bypassed_true_when_scanner_returns_true(self) -> None:
        self.mock_scanner.scan.return_value = _make_scan_result(bypassed=True)
        results = self._audit_with([_make_seed()])
        assert results[0].bypassed is True

    def test_result_bypassed_false_when_scanner_returns_false(self) -> None:
        self.mock_scanner.scan.return_value = _make_scan_result(bypassed=False)
        results = self._audit_with([_make_seed()])
        assert results[0].bypassed is False

    def test_result_score_from_scanner(self) -> None:
        self.mock_scanner.scan.return_value = _make_scan_result(score=0.75)
        results = self._audit_with([_make_seed()])
        assert results[0].score == 0.75

    def test_results_are_probe_result_instances(self) -> None:
        results = self._audit_with([_make_seed()])
        assert all(isinstance(r, ProbeResult) for r in results)

    def test_empty_dataset_returns_no_results(self) -> None:
        assert self._audit_with([]) == []


# ---------------------------------------------------------------------------
# audit — LLM path
# ---------------------------------------------------------------------------


class TestAuditLLM:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        _pyrit_setup_mod.initialize_pyrit_async.reset_mock()

        self.mock_target = MagicMock()
        self.mock_scorer = MagicMock()

        self.mock_response = _make_llm_response("LLM output")
        self.mock_target.send_prompt_async = AsyncMock(
            return_value=[self.mock_response]
        )

        self.mock_score = _make_score(True)
        self.mock_scorer.score_async = AsyncMock(return_value=[self.mock_score])

    def _audit_with(self, seeds: list) -> list[ProbeResult]:
        dataset = _make_dataset(seeds=seeds)
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async = AsyncMock(
            return_value=[dataset]
        )
        auditor = _make_llm_auditor(
            settings=PyritSettings(dataset_names=["x"]),
            llm_settings=LLMSettings(model="gpt-4o"),
        )
        with (
            patch.object(auditor, "_init_target", return_value=self.mock_target),
            patch.object(auditor, "_init_scorer", return_value=self.mock_scorer),
        ):
            return auditor.audit()

    def test_returns_one_result_per_seed(self) -> None:
        assert len(self._audit_with([_make_seed(), _make_seed()])) == 2

    def test_sends_prompt_to_target_for_each_seed(self) -> None:
        self._audit_with([_make_seed("p1"), _make_seed("p2")])
        assert self.mock_target.send_prompt_async.call_count == 2

    def test_scores_each_response(self) -> None:
        self._audit_with([_make_seed(), _make_seed()])
        assert self.mock_scorer.score_async.call_count == 2

    def test_scorer_receives_response_as_message(self) -> None:
        self._audit_with([_make_seed()])
        call_kwargs = self.mock_scorer.score_async.call_args.kwargs
        assert call_kwargs["message"] is self.mock_response

    def test_scorer_receives_prompt_as_objective(self) -> None:
        self._audit_with([_make_seed("attack text")])
        call_kwargs = self.mock_scorer.score_async.call_args.kwargs
        assert call_kwargs["objective"] == "attack text"

    def test_result_auditor_is_pyrit(self) -> None:
        results = self._audit_with([_make_seed()])
        assert results[0].auditor == "pyrit"

    def test_result_prompt_from_seed(self) -> None:
        results = self._audit_with([_make_seed("my prompt")])
        assert results[0].prompt == "my prompt"

    def test_result_attack_category_from_harm_categories(self) -> None:
        results = self._audit_with([_make_seed(harm_categories=["hate", "violence"])])
        assert results[0].attack_category == "hate,violence"

    def test_result_attack_type_is_default(self) -> None:
        results = self._audit_with([_make_seed()])
        assert results[0].attack_type == "default"

    def test_result_response_from_target(self) -> None:
        self.mock_response.get_value.return_value = "generated reply"
        results = self._audit_with([_make_seed()])
        assert results[0].response == "generated reply"

    def test_result_bypassed_true_when_score_true(self) -> None:
        self.mock_score.get_value.return_value = True
        results = self._audit_with([_make_seed()])
        assert results[0].bypassed is True

    def test_result_bypassed_false_when_score_false(self) -> None:
        self.mock_score.get_value.return_value = False
        results = self._audit_with([_make_seed()])
        assert results[0].bypassed is False

    def test_result_score_1_when_bypassed(self) -> None:
        self.mock_score.get_value.return_value = True
        results = self._audit_with([_make_seed()])
        assert results[0].score == 1.0

    def test_result_score_0_when_not_bypassed(self) -> None:
        self.mock_score.get_value.return_value = False
        results = self._audit_with([_make_seed()])
        assert results[0].score == 0.0

    def test_results_are_probe_result_instances(self) -> None:
        results = self._audit_with([_make_seed()])
        assert all(isinstance(r, ProbeResult) for r in results)

    def test_empty_dataset_returns_no_results(self) -> None:
        assert self._audit_with([]) == []

    def test_calls_init_target(self) -> None:
        dataset = _make_dataset(seeds=[])
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async = AsyncMock(
            return_value=[dataset]
        )
        auditor = _make_llm_auditor(
            settings=PyritSettings(dataset_names=["x"]),
            llm_settings=LLMSettings(model="gpt-4o"),
        )
        with (
            patch.object(
                auditor, "_init_target", return_value=self.mock_target
            ) as m_target,
            patch.object(auditor, "_init_scorer", return_value=self.mock_scorer),
        ):
            auditor.audit()
        m_target.assert_called_once()

    def test_calls_init_scorer(self) -> None:
        dataset = _make_dataset(seeds=[])
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async = AsyncMock(
            return_value=[dataset]
        )
        auditor = _make_llm_auditor(
            settings=PyritSettings(dataset_names=["x"]),
            llm_settings=LLMSettings(model="gpt-4o"),
        )
        with (
            patch.object(auditor, "_init_target", return_value=self.mock_target),
            patch.object(
                auditor, "_init_scorer", return_value=self.mock_scorer
            ) as m_scorer,
        ):
            auditor.audit()
        m_scorer.assert_called_once()


# ---------------------------------------------------------------------------
# audit — MULTITURN path (attack_strategies)
# ---------------------------------------------------------------------------


def _make_multiturn_auditor(
    settings: PyritSettings | None = None,
    llm_settings: LLMSettings | None = None,
) -> PyritProbe:
    auditor = _make_auditor(settings, llm_settings)
    auditor.target_type = TargetType.MULTITURN
    return auditor


class TestAuditMultiturn:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        _pyrit_setup_mod.initialize_pyrit_async.reset_mock()
        self.mock_target = MagicMock()
        self.mock_scorer = MagicMock()
        self.mock_scanner = MagicMock()

    def _run_multiturn(
        self, settings: PyritSettings, run_strategy_return: MagicMock | None = None
    ) -> list[ProbeResult]:
        dataset = _make_dataset(seeds=[_make_seed()])
        _pyrit_datasets_mod.SeedDatasetProvider.fetch_datasets_async = AsyncMock(
            return_value=[dataset]
        )
        if run_strategy_return is None:
            run_strategy_return = MagicMock()
            run_strategy_return.conversation_id = "cid"
            run_strategy_return.outcome = MagicMock()
            run_strategy_return.last_score = None

        auditor = _make_multiturn_auditor(settings=settings)
        auditor._scanner = self.mock_scanner
        with (
            patch.object(auditor, "_init_target", return_value=self.mock_target),
            patch.object(auditor, "_init_scorer", return_value=self.mock_scorer),
            patch.object(
                auditor,
                "_run_strategy_async",
                new=AsyncMock(return_value=run_strategy_return),
            ) as mock_run,
            patch.object(auditor, "_build_probe_results", return_value=[]),
        ):
            auditor.audit()
            return mock_run.call_args_list

    def test_explicit_strategies_are_used(self) -> None:
        from pentester.enums.attack_strategy import MultiTurnStrategy

        calls = self._run_multiturn(
            PyritSettings(
                dataset_names=["x"],
                attack_strategies=[MultiTurnStrategy.CRESCENDO],
            )
        )
        strategies_used = [c.kwargs["strategy"] for c in calls]
        assert strategies_used == [MultiTurnStrategy.CRESCENDO]

    def test_empty_strategies_runs_all(self) -> None:
        from pentester.enums.attack_strategy import MultiTurnStrategy

        calls = self._run_multiturn(
            PyritSettings(dataset_names=["x"], attack_strategies=[])
        )
        strategies_used = {c.kwargs["strategy"] for c in calls}
        assert strategies_used == set(MultiTurnStrategy)


# ---------------------------------------------------------------------------
# _init_objective_target
# ---------------------------------------------------------------------------


class TestInitObjectiveTarget:
    def test_returns_scanner_target_when_scanner_set(self) -> None:
        auditor = _make_auditor()
        auditor._scanner = MagicMock()
        result = auditor._init_objective_target()
        assert isinstance(result, ScannerTarget)

    def test_scanner_target_wraps_injected_scanner(self) -> None:
        mock_scanner = MagicMock()
        auditor = _make_auditor()
        auditor._scanner = mock_scanner
        result = auditor._init_objective_target()
        assert result.scanner is mock_scanner

    def test_returns_llm_target_when_scanner_is_none(self) -> None:
        auditor = _make_auditor(llm_settings=LLMSettings(model="gpt-4o"))
        auditor._scanner = None
        mock_llm_target = MagicMock()
        with patch.object(auditor, "_init_target", return_value=mock_llm_target):
            result = auditor._init_objective_target()
        assert result is mock_llm_target


def test_auditor_key_is_pyrit() -> None:
    assert _make_auditor().auditor_key == AuditorKey.PYRIT
