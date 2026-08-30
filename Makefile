install:
	uv pip install -e ".[test]"

clean:
	rm -rf build dist *.egg-info
	rm -rf examples/*.ll examples/*.o
	rm -rf htmlcov .coverage

# Regenerate the master vmlinux.py from the running kernel's BTF, then
# symlink it into every directory under tests/ so both pytest (which
# resolves "import vmlinux" via pythonpath=["."]) and any test file run
# standalone from its own directory see the same, always-fresh fixture.
vmlinux:
	python3 tools/vmlinux-gen.py -o vmlinux.py
	@find tests -type d -not -path '*/__pycache__*' | while read -r d; do \
		target=$$(python3 -c "import os,sys; print(os.path.relpath('vmlinux.py', sys.argv[1]))" "$$d"); \
		ln -sf "$$target" "$$d/vmlinux.py"; \
	done

test: vmlinux
	pytest tests/ -W ignore::DeprecationWarning -v --tb=short -m "not verifier"

test-cov: vmlinux
	pytest tests/ -W ignore::DeprecationWarning -v --tb=short -m "not verifier" \
		--cov=pythonbpf --cov-report=term-missing --cov-report=html

test-verifier: vmlinux
	@echo "NOTE: verifier tests shell out to 'sudo bpftool'; run 'sudo -v' first so"
	@echo "      the timestamp does not lapse mid-run. bpftool must be installed."
	pytest tests/test_verifier.py -W ignore::DeprecationWarning -v --tb=short -m verifier

all: clean install

.PHONY: all clean install test test-cov test-verifier vmlinux
