"""Tests for pentester.enums.true_meaning.TrueMeaning."""

import pytest

from pentester.enums.true_meaning import TrueMeaning


class TestTrueMeaningEnum:
    @pytest.mark.parametrize("member", list(TrueMeaning))
    def test_enum_integrity(self, member: TrueMeaning) -> None:
        """Each member is a string whose value is its lowercase name."""
        assert isinstance(member, str), f"{member.name} is not a string"
        assert member.value == member.name.lower()

    def test_bypassed_member_exists(self) -> None:
        assert TrueMeaning.BYPASSED == "bypassed"

    def test_blocked_member_exists(self) -> None:
        assert TrueMeaning.BLOCKED == "blocked"

    def test_has_exactly_two_members(self) -> None:
        assert len(list(TrueMeaning)) == 2
