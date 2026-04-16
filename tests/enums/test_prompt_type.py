"""Tests for pentester.enums.prompt_type.PromptType."""

import pytest

from pentester.enums.prompt_type import PromptType


class TestPromptTypeEnum:
    def test_has_exactly_two_members(self) -> None:
        assert len(list(PromptType)) == 2

    def test_single_value(self) -> None:
        assert PromptType.SINGLE == "single"

    def test_multiturn_value(self) -> None:
        assert PromptType.MULTITURN == "multiturn"

    @pytest.mark.parametrize("member", list(PromptType))
    def test_members_are_strings(self, member: PromptType) -> None:
        assert isinstance(member, str)

    def test_value_single_equals_string(self) -> None:
        assert PromptType.SINGLE == "single"

    def test_value_multiturn_equals_string(self) -> None:
        assert PromptType.MULTITURN == "multiturn"
