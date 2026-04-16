from pentester.auditors.models.probe_result import ProbeResult
from pentester.enums.prompt_type import PromptType


def _make_result(**kwargs) -> ProbeResult:
    defaults = {
        "auditor": "prompt_injector",
        "attack_category": "prompt",
        "attack_type": "injection",
        "prompt": "Ignore previous instructions.",
        "response": "Access denied.",
        "bypassed": False,
        "score": 0.0,
    }
    return ProbeResult(**{**defaults, **kwargs})


def test_all_fields_assigned() -> None:
    r = _make_result()
    assert r.auditor == "prompt_injector"
    assert r.attack_category == "prompt"
    assert r.attack_type == "injection"
    assert r.prompt == "Ignore previous instructions."
    assert r.response == "Access denied."
    assert r.bypassed is False
    assert r.score == 0.0
    assert r.prompt_type == PromptType.SINGLE
    assert r.metadata == {}


class TestPromptType:
    def test_default_is_single(self) -> None:
        assert _make_result().prompt_type == PromptType.SINGLE

    def test_single_value_accepted(self) -> None:
        r = _make_result(prompt_type=PromptType.SINGLE)
        assert r.prompt_type == PromptType.SINGLE

    def test_multiturn_value_accepted(self) -> None:
        r = _make_result(prompt_type=PromptType.MULTITURN)
        assert r.prompt_type == PromptType.MULTITURN


def test_bypassed_true() -> None:
    r = _make_result(bypassed=True)
    assert r.bypassed is True


def test_field_override() -> None:
    r = _make_result(auditor="xss_tool", score=0.9)
    assert r.auditor == "xss_tool"
    assert r.score == 0.9


def test_metadata_defaults_to_empty_dict() -> None:
    r = _make_result()
    assert r.metadata == {}


def test_metadata_can_be_set() -> None:
    r = _make_result(metadata={"key": "value"})
    assert r.metadata == {"key": "value"}


def test_two_instances_with_same_values_are_equal() -> None:
    r1 = _make_result()
    r2 = _make_result()
    assert r1 == r2


def test_two_instances_with_different_values_are_not_equal() -> None:
    r1 = _make_result(bypassed=False)
    r2 = _make_result(bypassed=True)
    assert r1 != r2


def test_is_error_true_when_error_in_metadata() -> None:
    r = _make_result(metadata={"error": "HTTP 422"})
    assert r.is_error is True


def test_is_error_false_when_no_error_in_metadata() -> None:
    r = _make_result()
    assert r.is_error is False


def test_is_error_false_when_error_is_none() -> None:
    r = _make_result(metadata={"error": None})
    assert r.is_error is False


class TestFormattedPrompt:
    def test_plain_ascii_is_unchanged(self) -> None:
        r = _make_result(prompt="hello world")
        assert r.formatted_prompt == "hello world"

    def test_unicode_char_is_escaped(self) -> None:
        r = _make_result(prompt="caf\u00e9")
        assert r.formatted_prompt == "caf\\xe9"

    def test_newline_is_escaped(self) -> None:
        r = _make_result(prompt="line1\nline2")
        assert r.formatted_prompt == "line1\\nline2"

    def test_double_quote_is_not_csv_escaped(self) -> None:
        r = _make_result(prompt='say "hello"')
        assert r.formatted_prompt == 'say "hello"'


class TestFormattedPromptMd:
    def test_pipe_is_escaped(self) -> None:
        r = _make_result(prompt="step 1 | step 2 | step 3")
        assert r.formatted_prompt_md == "step 1 \\| step 2 \\| step 3"

    def test_no_pipe_is_unchanged(self) -> None:
        r = _make_result(prompt="hello world")
        assert r.formatted_prompt_md == "hello world"

    def test_unicode_and_pipe_both_handled(self) -> None:
        r = _make_result(prompt="caf\u00e9 | enjoy")
        assert r.formatted_prompt_md == "caf\\xe9 \\| enjoy"


def test_duration_defaults_to_none() -> None:
    assert _make_result().duration is None


def test_duration_can_be_set() -> None:
    assert _make_result(duration=1.23).duration == 1.23


def test_formatted_duration_when_set() -> None:
    assert _make_result(duration=1.234567).formatted_duration == "1.235s"


def test_formatted_duration_when_none() -> None:
    assert _make_result(duration=None).formatted_duration == "—"


class TestJudgeReason:
    def test_returns_none_when_metadata_is_empty(self) -> None:
        assert _make_result().judge_reason is None

    def test_returns_none_when_key_absent(self) -> None:
        assert _make_result(metadata={"error": "oops"}).judge_reason is None

    def test_returns_reason_when_set(self) -> None:
        assert (
            _make_result(metadata={"judge_reason": "Safe response"}).judge_reason
            == "Safe response"
        )
