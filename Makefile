install:
	uv pip install -e ".[test]"

clean:
	rm -rf build dist *.egg-info
	rm -rf examples/*.ll examples/*.o
	rm -rf htmlcov .coverage

test:
	pytest tests/ -W ignore::DeprecationWarning -v --tb=short -m "not verifier"

test-cov:
	pytest tests/ -W ignore::DeprecationWarning -v --tb=short -m "not verifier" \
		--cov=pythonbpf --cov-report=term-missing --cov-report=html

test-verifier:
	@echo "NOTE: verifier tests shell out to 'sudo bpftool'; run 'sudo -v' first so"
	@echo "      the timestamp does not lapse mid-run. bpftool must be installed."
	pytest tests/test_verifier.py -W ignore::DeprecationWarning -v --tb=short -m verifier

all: clean install

.PHONY: all clean install test test-cov test-verifier
