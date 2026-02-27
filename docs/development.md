## Linter, hints and formatting

This project uses Ruff and Mypy

### Commands

* Format, `ruff format`
* Linter, `ruff check`
* Mypy, `mypy ./src`

## Tests

This project uses pytest, pytest-mock and pytest-cov for unit testing

### Commands

* Testing, `pytest -v`
* Testing Watcher, `ptw .`
* Coverage, `pytest -v --cov=src`

## Try package locally

1, Build the project, `python -m build`
2. Install the wheel file `pip install ./dist/pentester-{version}-py3-none-any.whl`
3. Run the sample file `python sample.py`