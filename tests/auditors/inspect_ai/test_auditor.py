"""Tests for pentester.auditors.inspect_ai.auditor.InspectAIAuditor."""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Re-read stubs registered by conftest.pytest_configure so helpers reference
# the same CORRECT/INCORRECT strings used by the module under test.
_inspect_ai_scorer_mod = sys.modules["inspect_ai.scorer"]
_inspect_ai_mod = sys.modules["inspect_ai"]
_CORRECT = _inspect_ai_scorer_mod.CORRECT
_INCORRECT = _inspect_ai_scorer_mod.INCORRECT

from pentester.auditors.inspect_ai.auditor import InspectAIAuditor  # noqa: E402
from pentester.auditors.models.probe_result import ProbeResult  # noqa: E402
from pentester.config.auditors.inspect_settings import InspectSettings  # noqa: E402
from pentester.config.settings import TargetType  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auditor(**kwargs: Any) -> InspectAIAuditor:
    auditor = InspectAIAuditor(settings=InspectSettings(**kwargs))
    auditor.target_type = TargetType.LLM
    return auditor


def _make_score(value: Any = None, explanation: str = "judge reasoning") -> MagicMock:
    score = MagicMock()
    score.value = value if value is not None else _CORRECT
    score.explanation = explanation
    return score


def _make_sample(
    input_text: Any = "attack prompt",
    completion: str = "model response",
    score_value: Any = None,
    metadata: dict[str, Any] | None = None,
    sample_id: Any = "sample-1",
) -> MagicMock:
    sample = MagicMock()
    sample.input = input_text
    sample.output.completion = completion
    sample.scores = {
        "security_scorer": _make_score(
            score_value if score_value is not None else _CORRECT
        )
    }
    sample.metadata = metadata if metadata is not None else {}
    sample.id = sample_id
    return sample


def _make_log(samples: list[MagicMock] | None = None) -> MagicMock:
    log = MagicMock()
    log.samples = samples
    return log


# ---------------------------------------------------------------------------
# TestInterpretScore
# ---------------------------------------------------------------------------


class TestInterpretScore:
    def _run(
        self, score: MagicMock | None, score_max: float = 1.0
    ) -> tuple[bool, float]:
        return _make_auditor()._interpret_score(score, score_max=score_max)

    def test_correct_returns_bypassed_true_score_one(self) -> None:
        bypassed, score = self._run(_make_score(_CORRECT))
        assert bypassed is True
        assert score == 1.0

    def test_incorrect_returns_bypassed_false_score_zero(self) -> None:
        bypassed, score = self._run(_make_score(_INCORRECT))
        assert bypassed is False
        assert score == 0.0

    def test_none_returns_bypassed_false_score_zero(self) -> None:
        bypassed, score = self._run(None)
        assert bypassed is False
        assert score == 0.0

    def test_numeric_above_threshold_returns_bypassed_true(self) -> None:
        bypassed, score = self._run(_make_score(0.8))
        assert bypassed is True
        assert score == pytest.approx(0.8)

    def test_numeric_at_threshold_returns_bypassed_true(self) -> None:
        bypassed, _ = self._run(_make_score(0.5))
        assert bypassed is True

    def test_numeric_below_threshold_returns_bypassed_false(self) -> None:
        bypassed, score = self._run(_make_score(0.3))
        assert bypassed is False
        assert score == pytest.approx(0.3)

    def test_numeric_clamped_above_one(self) -> None:
        _, score = self._run(_make_score(5.0))
        assert score == pytest.approx(1.0)

    def test_numeric_clamped_below_zero(self) -> None:
        bypassed, score = self._run(_make_score(-1.0))
        assert bypassed is False
        assert score == pytest.approx(0.0)

    def test_numeric_normalized_by_score_max(self) -> None:
        # value=2.5 out of max=5.0 → 0.5 → bypassed
        bypassed, score = self._run(_make_score(2.5), score_max=5.0)
        assert bypassed is True
        assert score == pytest.approx(0.5)

    def test_unknown_string_returns_bypassed_false(self) -> None:
        bypassed, score = self._run(_make_score("unknown"))
        assert bypassed is False
        assert score == 0.0


# ---------------------------------------------------------------------------
# TestExtractAttackFields
# ---------------------------------------------------------------------------


class TestExtractAttackFields:
    def _run(
        self,
        metadata: dict[str, Any],
        eval_name: str = "strong_reject",
    ) -> tuple[str, str]:
        sample = _make_sample(metadata=metadata)
        return _make_auditor()._extract_attack_fields(sample, eval_name)

    def test_uses_category_from_metadata(self) -> None:
        category, _ = self._run(
            {"category": "prompt_injection", "attack_type": "ignore_prev"}
        )
        assert category == "prompt_injection"

    def test_uses_attack_type_from_metadata(self) -> None:
        _, attack_type = self._run(
            {"category": "prompt_injection", "attack_type": "ignore_prev"}
        )
        assert attack_type == "ignore_prev"

    def test_falls_back_to_eval_name_when_category_missing(self) -> None:
        category, _ = self._run({}, eval_name="strong_reject")
        assert category == "strong_reject"

    def test_attack_type_falls_back_to_category_when_missing(self) -> None:
        category, attack_type = self._run({"category": "jailbreak"})
        assert attack_type == category

    def test_both_fall_back_to_eval_name(self) -> None:
        category, attack_type = self._run({}, eval_name="b3")
        assert category == "b3"
        assert attack_type == "b3"

    def test_strips_whitespace_from_metadata_values(self) -> None:
        category, attack_type = self._run(
            {"category": "  pi  ", "attack_type": "  t  "}
        )
        assert category == "pi"
        assert attack_type == "t"

    def test_empty_string_metadata_treated_as_missing(self) -> None:
        category, _ = self._run({"category": ""}, eval_name="agentharm")
        assert category == "agentharm"


# ---------------------------------------------------------------------------
# TestExtractPrompt
# ---------------------------------------------------------------------------


class TestExtractPrompt:
    def _run(self, input_text: Any) -> str:
        sample = _make_sample(input_text=input_text)
        return _make_auditor()._extract_prompt(sample)

    def test_string_input_returned_directly(self) -> None:
        assert self._run("attack string") == "attack string"

    def test_list_input_returns_last_user_message_content(self) -> None:
        msg1 = MagicMock()
        msg1.content = "system msg"
        msg2 = MagicMock()
        msg2.content = "user attack"
        assert self._run([msg1, msg2]) == "user attack"

    def test_list_input_skips_messages_without_string_content(self) -> None:
        msg_bad = MagicMock()
        msg_bad.content = None
        msg_good = MagicMock()
        msg_good.content = "real attack"
        assert self._run([msg_good, msg_bad]) == "real attack"

    def test_empty_list_returns_empty_string(self) -> None:
        assert self._run([]) == ""

    def test_non_string_non_list_returns_empty_string(self) -> None:
        assert self._run(None) == ""


# ---------------------------------------------------------------------------
# TestGetTask
# ---------------------------------------------------------------------------


class TestGetTask:
    def test_known_eval_returns_task(self) -> None:
        auditor = _make_auditor()
        result = auditor._get_task("b3")
        assert result is not None

    def test_unknown_eval_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown eval name"):
            _make_auditor()._get_task("nonexistent_eval")

    def test_strong_reject_passes_judge_llm(self) -> None:
        factory = MagicMock()
        auditor = _make_auditor(judge_model="openai/gpt-4o-mini")
        with patch.dict(
            "pentester.auditors.inspect_ai.auditor._EVAL_REGISTRY",
            {"strong_reject": factory},
        ):
            auditor._get_task("strong_reject")
        factory.assert_called_once_with(judge_llm="openai/gpt-4o-mini")

    def test_non_strong_reject_eval_called_with_no_args_for_llm(self) -> None:
        factory = MagicMock()
        auditor = _make_auditor()  # target_type = LLM
        with patch.dict(
            "pentester.auditors.inspect_ai.auditor._EVAL_REGISTRY", {"b3": factory}
        ):
            auditor._get_task("b3")
        factory.assert_called_once_with()

    def test_b3_fence_target_called_with_task_types(self) -> None:
        factory = MagicMock()
        auditor = InspectAIAuditor(settings=InspectSettings(), scanner=MagicMock())
        auditor.target_type = TargetType.SEMANTIC_FENCE
        with patch.dict(
            "pentester.auditors.inspect_ai.auditor._EVAL_REGISTRY", {"b3": factory}
        ):
            auditor._get_task("b3")
        factory.assert_called_once_with(task_types=["DIO", "IIO"])


# ---------------------------------------------------------------------------
# TestMapSample
# ---------------------------------------------------------------------------


class TestMapSample:
    def test_maps_auditor_name(self) -> None:
        sample = _make_sample()
        result = _make_auditor()._map_sample(sample, "strong_reject")
        assert result.auditor == "inspect_ai"

    def test_maps_prompt_from_input(self) -> None:
        sample = _make_sample(input_text="my attack")
        result = _make_auditor()._map_sample(sample, "strong_reject")
        assert result.prompt == "my attack"

    def test_maps_response_from_output_completion(self) -> None:
        sample = _make_sample(completion="model said this")
        result = _make_auditor()._map_sample(sample, "strong_reject")
        assert result.response == "model said this"

    def test_bypassed_true_when_correct(self) -> None:
        sample = _make_sample(score_value=_CORRECT)
        result = _make_auditor()._map_sample(sample, "strong_reject")
        assert result.bypassed is True

    def test_bypassed_false_when_incorrect(self) -> None:
        sample = _make_sample(score_value=_INCORRECT)
        result = _make_auditor()._map_sample(sample, "strong_reject")
        assert result.bypassed is False

    def test_score_one_when_correct(self) -> None:
        sample = _make_sample(score_value=_CORRECT)
        result = _make_auditor()._map_sample(sample, "strong_reject")
        assert result.score == pytest.approx(1.0)

    def test_score_zero_when_incorrect(self) -> None:
        sample = _make_sample(score_value=_INCORRECT)
        result = _make_auditor()._map_sample(sample, "strong_reject")
        assert result.score == pytest.approx(0.0)

    def test_metadata_includes_sample_id(self) -> None:
        sample = _make_sample(sample_id="abc-123")
        result = _make_auditor()._map_sample(sample, "strong_reject")
        assert result.metadata["sample_id"] == "abc-123"

    def test_metadata_includes_score_value(self) -> None:
        sample = _make_sample(score_value=_CORRECT)
        result = _make_auditor()._map_sample(sample, "strong_reject")
        assert result.metadata["score_value"] == _CORRECT

    def test_no_output_returns_empty_response(self) -> None:
        sample = _make_sample()
        sample.output = None
        result = _make_auditor()._map_sample(sample, "strong_reject")
        assert result.response == ""

    def test_returns_probe_result_instance(self) -> None:
        result = _make_auditor()._map_sample(_make_sample(), "strong_reject")
        assert isinstance(result, ProbeResult)


# ---------------------------------------------------------------------------
# TestMapResults
# ---------------------------------------------------------------------------


class TestMapResults:
    def test_returns_empty_list_when_samples_is_none(self) -> None:
        log = _make_log(samples=None)
        results = _make_auditor()._map_results(log, "b3")
        assert results == []

    def test_maps_all_samples_to_probe_results(self) -> None:
        samples = [_make_sample(), _make_sample()]
        log = _make_log(samples=samples)
        results = _make_auditor()._map_results(log, "b3")
        assert len(results) == 2

    def test_skips_sample_that_raises_and_continues(self) -> None:
        good_sample = _make_sample()
        auditor = _make_auditor()
        call_count = 0

        def _map_side_effect(sample: Any, eval_name: str) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("bad sample")
            return ProbeResult(
                auditor="inspect_ai",
                attack_category="cat",
                attack_type="type",
                prompt="p",
                response="r",
                bypassed=False,
                score=0.0,
            )

        log = _make_log(samples=[MagicMock(), good_sample])
        with patch.object(auditor, "_map_sample", side_effect=_map_side_effect):
            results = auditor._map_results(log, "b3")
        assert len(results) == 1


# ---------------------------------------------------------------------------
# TestAudit
# ---------------------------------------------------------------------------


class TestAudit:
    def test_returns_empty_when_scanner_is_none(self) -> None:
        auditor = InspectAIAuditor(settings=InspectSettings(), scanner=None)
        assert auditor.audit() == []

    def test_iterates_all_evals(self) -> None:
        mock_scanner = MagicMock()
        auditor = InspectAIAuditor(
            settings=InspectSettings(evals=["b3", "agentharm"]),
            scanner=mock_scanner,
        )
        with (
            patch.object(auditor, "_get_task", return_value=MagicMock()) as m_task,
            patch.object(auditor, "_map_results", return_value=[]),
        ):
            _inspect_ai_mod.eval.return_value = [_make_log(samples=[])]
            auditor.audit()
        assert m_task.call_count == 2

    def test_aggregates_results_from_all_evals(self) -> None:
        mock_scanner = MagicMock()
        auditor = InspectAIAuditor(
            settings=InspectSettings(evals=["b3", "agentharm"]),
            scanner=mock_scanner,
        )

        def _make_result() -> ProbeResult:
            return ProbeResult(
                auditor="inspect_ai",
                attack_category="cat",
                attack_type="type",
                prompt="p",
                response="r",
                bypassed=True,
                score=1.0,
            )

        with (
            patch.object(auditor, "_get_task", return_value=MagicMock()),
            patch.object(
                auditor,
                "_map_results",
                side_effect=[[_make_result()], [_make_result()]],
            ),
            patch("pentester.auditors.inspect_ai.auditor.inspect_eval") as m_eval,
        ):
            m_eval.return_value = [_make_log(samples=[])]
            results = auditor.audit()
        assert len(results) == 2

    def test_isolates_exception_per_eval(self) -> None:
        mock_scanner = MagicMock()
        auditor = InspectAIAuditor(
            settings=InspectSettings(evals=["b3", "agentharm"]),
            scanner=mock_scanner,
        )
        call_count = 0

        def _get_task_side_effect(eval_name: str) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("eval load failed")
            return MagicMock()

        with (
            patch.object(auditor, "_get_task", side_effect=_get_task_side_effect),
            patch.object(auditor, "_map_results", return_value=[]),
        ):
            _inspect_ai_mod.eval.return_value = [_make_log(samples=[])]
            results = auditor.audit()
        assert results == []

    def test_returns_empty_list_when_all_evals_fail(self) -> None:
        mock_scanner = MagicMock()
        auditor = InspectAIAuditor(
            settings=InspectSettings(evals=["b3"]),
            scanner=mock_scanner,
        )
        with patch.object(auditor, "_get_task", side_effect=RuntimeError("fail")):
            results = auditor.audit()
        assert results == []

    def test_passes_scanner_model_to_inspect_eval(self) -> None:
        mock_scanner = MagicMock()
        auditor = InspectAIAuditor(
            settings=InspectSettings(evals=["b3"]),
            scanner=mock_scanner,
        )
        mock_model = MagicMock(name="scanner_model")
        with (
            patch.object(auditor, "_get_task", return_value=MagicMock()),
            patch.object(auditor, "_map_results", return_value=[]),
            patch("pentester.auditors.inspect_ai.auditor.inspect_eval") as m_eval,
            patch("inspect_ai.model.get_model", return_value=mock_model),
        ):
            m_eval.return_value = [_make_log(samples=[])]
            auditor.audit()
        call_kwargs = m_eval.call_args
        assert call_kwargs.kwargs.get("model") is mock_model or (
            call_kwargs.args and call_kwargs.args[1] is mock_model
        )


# ---------------------------------------------------------------------------
# TestDefaultEvalsForTarget
# ---------------------------------------------------------------------------


class TestDefaultEvalsForTarget:
    def test_fence_returns_only_three_evals(self) -> None:
        auditor = InspectAIAuditor(settings=InspectSettings(), scanner=MagicMock())
        auditor.target_type = TargetType.SEMANTIC_FENCE
        evals = auditor._default_evals_for_target()
        assert evals == ["strong_reject", "b3", "fortress_adversarial"]

    def test_llm_returns_all_five_evals(self) -> None:
        auditor = InspectAIAuditor(settings=InspectSettings(), scanner=MagicMock())
        auditor.target_type = TargetType.LLM
        evals = auditor._default_evals_for_target()
        assert evals == [
            "strong_reject",
            "b3",
            "fortress_adversarial",
            "agentharm",
            "AgentDojo",
        ]

    def test_settings_evals_override_takes_precedence(self) -> None:
        auditor = InspectAIAuditor(
            settings=InspectSettings(evals=["b3"]), scanner=MagicMock()
        )
        auditor.target_type = TargetType.SEMANTIC_FENCE
        assert auditor._settings.evals == ["b3"]

    def test_empty_settings_evals_uses_fence_defaults(self) -> None:
        auditor = InspectAIAuditor(
            settings=InspectSettings(evals=[]), scanner=MagicMock()
        )
        auditor.target_type = TargetType.SEMANTIC_FENCE
        effective = auditor._settings.evals or auditor._default_evals_for_target()
        assert effective == ["strong_reject", "b3", "fortress_adversarial"]

    def test_empty_settings_evals_uses_llm_defaults(self) -> None:
        auditor = InspectAIAuditor(
            settings=InspectSettings(evals=[]), scanner=MagicMock()
        )
        auditor.target_type = TargetType.LLM
        effective = auditor._settings.evals or auditor._default_evals_for_target()
        assert "agentharm" in effective
        assert "AgentDojo" in effective


# ---------------------------------------------------------------------------
# TestGetTaskFenceScorer
# ---------------------------------------------------------------------------


class TestGetTaskFenceScorer:
    def test_llm_target_does_not_override_scorer(self) -> None:
        mock_scanner = MagicMock()
        mock_task = MagicMock()
        factory = MagicMock(return_value=mock_task)
        original_scorer = mock_task.scorer
        auditor = InspectAIAuditor(settings=InspectSettings(), scanner=mock_scanner)
        auditor.target_type = TargetType.LLM
        with patch.dict(
            "pentester.auditors.inspect_ai.auditor._EVAL_REGISTRY", {"b3": factory}
        ):
            task = auditor._get_task("b3")
        assert task.scorer is original_scorer

    def test_fence_target_sets_scorer_on_task(self) -> None:
        mock_scanner = MagicMock()
        mock_task = MagicMock()
        factory = MagicMock(return_value=mock_task)
        auditor = InspectAIAuditor(settings=InspectSettings(), scanner=mock_scanner)
        auditor.target_type = TargetType.SEMANTIC_FENCE
        with patch.dict(
            "pentester.auditors.inspect_ai.auditor._EVAL_REGISTRY", {"b3": factory}
        ):
            with patch.object(
                auditor, "_make_fence_scorer", return_value="fence"
            ) as m_make:
                auditor._get_task("b3")
        m_make.assert_called_once()
        assert mock_task.scorer == ["fence"]

    def test_fence_scorer_also_set_for_strong_reject(self) -> None:
        mock_scanner = MagicMock()
        mock_task = MagicMock()
        factory = MagicMock(return_value=mock_task)
        auditor = InspectAIAuditor(
            settings=InspectSettings(judge_model=None), scanner=mock_scanner
        )
        auditor.target_type = TargetType.SEMANTIC_FENCE
        with patch.dict(
            "pentester.auditors.inspect_ai.auditor._EVAL_REGISTRY",
            {"strong_reject": factory},
        ):
            with patch.object(auditor, "_make_fence_scorer", return_value="fence"):
                auditor._get_task("strong_reject")
        assert mock_task.scorer == ["fence"]


# ---------------------------------------------------------------------------
# TestMakeFenceScorer
# ---------------------------------------------------------------------------


class TestMakeFenceScorer:
    def test_returns_non_none_scorer(self) -> None:
        mock_scanner = MagicMock()
        auditor = InspectAIAuditor(settings=InspectSettings(), scanner=mock_scanner)
        result = auditor._make_fence_scorer()
        assert result is not None

    def test_returns_fence_scorer_api_score_method(self) -> None:
        import asyncio

        mock_scanner = MagicMock()
        auditor = InspectAIAuditor(settings=InspectSettings(), scanner=mock_scanner)
        result = auditor._make_fence_scorer()
        assert callable(result)
        assert asyncio.iscoroutinefunction(result)
