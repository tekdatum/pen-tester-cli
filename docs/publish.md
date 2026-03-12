# Pip Library Publishing Guide

This document outlines the necessary steps to update and publish the library to PyPI.

## Prerequisites

Before starting, ensure you have the following:

1. Install and activate the environment, this is described in the [setup](./setup.md) guide.
2.  **PyPI Token**: A valid API token from your [PyPI account](https://pypi.org/manage/account/token/).

## Publishing Process

Follow these steps to publish a new version:

### 0. Make sure peer-dependencies are updated

You need to install pipreqs, `pipreqs src/ --print`, and then add those
to the toml file in the dependencies section, you could use Gemini or similar to get
the right syntaxis 

### 1. Update the Version

Edit the `pyproject.toml` file and update the `version` field under the `[project]` section. Ensure you use semantic versioning (e.g., `0.0.3`).

```toml
[project]
name = "pentester"
version = "0.0.3"  <-- Update this
...
```

### 2. Configure the Authentication Token

Export your PyPI token as an environment variable. This is required for `publish.sh` to authenticate.

```bash
export PYPI_TOKEN=pypi-yourtokenstringhere...
```
*Note: It is recommended not to save this token in files tracked by git.*

### 3. Run the Publish Script

Make sure the environment is activated inside your terminal.

Execute the `publish.sh` script. This script will:
- Clean previous distributions (`dist/`).
- Build the package (`python -m build`).
- Upload the package to PyPI using `twine`.

```bash
bash ./publish.sh
```

If successful, you will see output from `twine` confirming the upload.

#### Using testpypi for testing

To avoid adding incorrect version to the main registry you can use your personal
`test.pypi.com` account to publish the libraries

You can publish to test pypi by adding `--repository tespypi` to the twine upload command 

```bash
python -m twine upload --repository testpypi dist/*
```

You can install from test pypi using this command
```bash
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            pentester==0.0.2
```


## Troubleshooting

-   **Error: PYPI_TOKEN is not defined**: Ensure you ran the `export` command from step 2 in the same terminal session where you are running the script.
-   **Version already exists**: If PyPI rejects the upload, verify that you have incremented the version in `pyproject.toml` compared to the last version published on PyPI.