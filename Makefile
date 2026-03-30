install:
	uv pip install -e ".[test]"

clean:
	rm -rf build dist *.egg-info
	rm -rf examples/*.ll examples/*.o
	rm -rf htmlcov .coverage

test:
	pytest tests/ -v --tb=short -m "not verifier"

test-cov:
	pytest tests/ -v --tb=short -m "not verifier" \
		--cov=pythonbpf --cov-report=term-missing --cov-report=html

test-verifier:
	@echo "NOTE: verifier tests require sudo and bpftool. Uses sudo .venv/bin/python3."
	pytest tests/test_verifier.py -v --tb=short -m verifier

all: clean install

.PHONY: all clean install test test-cov test-verifier
