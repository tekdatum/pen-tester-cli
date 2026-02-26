#!/bin/bash

# Check if PYPI_TOKEN is set
if [ -z "$PYPI_TOKEN" ]; then
  echo "Error: The PYPI_TOKEN environment variable is not defined."
  echo "Please define your PyPI API token:"
  echo "export PYPI_TOKEN=pypi-..."
  exit 1
fi

rm -rf dist/*
python -m build
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD=$PYPI_TOKEN
python -m twine upload dist/*