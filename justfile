# Local macOS workflow. Requires Python 3.10+ and optional just.
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

bootstrap:
    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install -r requirements.txt

web:
    .venv/bin/python -m streamlit run app.py --server.address=127.0.0.1 --server.port=8501

ci:
    python3 -m compileall -q app.py web_core.py enpass_dedupe.py
    python3 -m unittest discover -s . -p 'test_*.py' -v

cli-help:
    python3 enpass_dedupe.py --help
