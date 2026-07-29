# Development environment

## 1. Create the environment

1. From the project root, create the venv:
    ```bash
    python3 -m venv pentester_env
    ```

2. Activate the virtual environment:
    ```bash
    source pentester_env/bin/activate
    ```

3. Install dependencies:
    ```bash
    python -m pip install -r requirements.txt
    python -m pip install garak==0.14.0
    ```

## 2. If your venv has no pip

Some systems (a minimal Python, or Debian/Ubuntu missing the `python3-venv`
`ensurepip` data) can't seed pip into a new venv. In that case step 1 either
errors with `ensurepip is not available` or produces a venv where `pip` is
missing. Create the venv without pip and bootstrap it manually with the
official installer:

```bash
python3 -m venv pentester_env --without-pip
source pentester_env/bin/activate
curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
rm get-pip.py
```

Then continue with step 3 above (`pip install -r requirements.txt`, etc.).