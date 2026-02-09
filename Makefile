.PHONY: venv install run smoke

venv:
	python -m venv .venv
	@echo "Run: source .venv/bin/activate"

install:
	pip install -r requirements.txt

run:
	python app.py

smoke:
	python -m compileall .
