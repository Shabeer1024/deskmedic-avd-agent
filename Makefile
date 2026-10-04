PY ?= python3.13
VENV := .venv
BIN := $(VENV)/bin

.PHONY: help setup run test lint clean demo

help:
	@echo "make setup   - create venv and install deps (mock mode, no Azure needed)"
	@echo "make run     - start the agent at http://127.0.0.1:8080"
	@echo "make test    - run unit + integration + safety tests"
	@echo "make lint    - ruff check"
	@echo "make demo    - run the scripted end-to-end Scenario 1 demo"
	@echo "make clean   - remove venv and runtime data"

setup:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"
	@test -f .env || cp .env.example .env
	@echo "Setup complete. Run: make run"

run:
	$(BIN)/uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8080 --reload

test:
	$(BIN)/pytest -q

lint:
	$(BIN)/ruff check backend tests

demo:
	$(BIN)/python scripts/demo_end_to_end.py

clean:
	rm -rf $(VENV) data .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

verify: lint test
	@echo "lint + tests clean"
