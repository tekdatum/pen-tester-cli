import pytest

from pentester.reporting.enum.generator_key import GeneratorKey


def test_pdf_value() -> None:
    assert GeneratorKey.PDF == "pdf"


def test_csv_value() -> None:
    assert GeneratorKey.CSV == "csv"


def test_html_value() -> None:
    assert GeneratorKey.HTML == "html"


def test_markdown_value() -> None:
    assert GeneratorKey.MARKDOWN == "markdown"


def test_all_keys_count() -> None:
    assert len(GeneratorKey) == 4


def test_all_key_names() -> None:
    assert {k.name for k in GeneratorKey} == {"PDF", "CSV", "HTML", "MARKDOWN"}


def test_is_str_subclass() -> None:
    assert isinstance(GeneratorKey.PDF, str)


def test_from_string_lookup() -> None:
    assert GeneratorKey("pdf") is GeneratorKey.PDF
    assert GeneratorKey("csv") is GeneratorKey.CSV
    assert GeneratorKey("html") is GeneratorKey.HTML
    assert GeneratorKey("markdown") is GeneratorKey.MARKDOWN


def test_invalid_string_raises_value_error() -> None:
    with pytest.raises(ValueError):
        GeneratorKey("xml")
