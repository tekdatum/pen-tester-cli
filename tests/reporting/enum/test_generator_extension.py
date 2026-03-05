import pytest

from pentester.reporting.enum.generator_extension import GeneratorExtension


def test_pdf_value() -> None:
    assert GeneratorExtension.PDF == "pdf"


def test_csv_value() -> None:
    assert GeneratorExtension.CSV == "csv"


def test_html_value() -> None:
    assert GeneratorExtension.HTML == "html"


def test_markdown_value() -> None:
    assert GeneratorExtension.MARKDOWN == "md"


def test_all_extensions_count() -> None:
    assert len(GeneratorExtension) == 4


def test_all_extension_names() -> None:
    assert {e.name for e in GeneratorExtension} == {"PDF", "CSV", "HTML", "MARKDOWN"}


def test_is_str_subclass() -> None:
    assert isinstance(GeneratorExtension.PDF, str)


def test_from_string_lookup() -> None:
    assert GeneratorExtension("pdf") is GeneratorExtension.PDF
    assert GeneratorExtension("csv") is GeneratorExtension.CSV
    assert GeneratorExtension("html") is GeneratorExtension.HTML
    assert GeneratorExtension("md") is GeneratorExtension.MARKDOWN


def test_invalid_string_raises_value_error() -> None:
    with pytest.raises(ValueError):
        GeneratorExtension("xml")
