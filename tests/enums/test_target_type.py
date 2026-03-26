"""Tests for pentester.enums.target_type.TargetType."""

import pytest

from pentester.enums.target_type import TargetType


class TestTargetTypeEnum:
    @pytest.mark.parametrize("member", list(TargetType))
    def test_enum_integrity(self, member: TargetType) -> None:
        """Validates that each member is a string and its value equals its name."""
        assert isinstance(member, str), f"{member.name} is not a string"
        assert member.value == member.name, (
            f"Value mismatch for '{member.name}': "
            f"expected '{member.name}', got '{member.value}'"
        )

    def test_llm_member_exists(self) -> None:
        assert TargetType.LLM == "LLM"

    def test_semantic_fence_member_exists(self) -> None:
        assert TargetType.SEMANTIC_FENCE == "SEMANTIC_FENCE"

    def test_has_exactly_three_members(self) -> None:
        assert len(list(TargetType)) == 3

    def test_multiturn_member_exists(self) -> None:
        assert TargetType.MULTITURN == "MULTITURN"
