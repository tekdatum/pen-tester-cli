from collections.abc import Generator

import pytest

from pentester.reporting.generators.csv_generator import CsvGenerator
from pentester.reporting.generators.generator_factory import GeneratorFactory
from pentester.reporting.generators.html_generator import HtmlGenerator
from pentester.reporting.generators.markdown_generator import MarkdownGenerator
from pentester.reporting.generators.pdf_generator import PdfGenerator


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    GeneratorFactory._instance = None
    yield
    GeneratorFactory._instance = None


def test_singleton_same_instance() -> None:
    assert GeneratorFactory() is GeneratorFactory()


def test_get_pdf_returns_pdf_generator() -> None:
    assert isinstance(GeneratorFactory().get("pdf"), PdfGenerator)


def test_get_csv_returns_csv_generator() -> None:
    assert isinstance(GeneratorFactory().get("csv"), CsvGenerator)


def test_get_html_returns_html_generator() -> None:
    assert isinstance(GeneratorFactory().get("html"), HtmlGenerator)


def test_get_markdown_returns_markdown_generator() -> None:
    assert isinstance(GeneratorFactory().get("markdown"), MarkdownGenerator)


def test_get_unknown_key_raises_value_error() -> None:
    with pytest.raises(ValueError):
        GeneratorFactory().get("xml")


def test_get_all_returns_generators_in_order() -> None:
    factory = GeneratorFactory()
    result = factory.get_all(["csv", "pdf"])
    assert isinstance(result[0], CsvGenerator)
    assert isinstance(result[1], PdfGenerator)


def test_get_all_empty_keys_returns_empty_list() -> None:
    assert GeneratorFactory().get_all([]) == []


def test_get_all_unknown_key_raises_value_error() -> None:
    with pytest.raises(ValueError):
        GeneratorFactory().get_all(["pdf", "unknown"])
