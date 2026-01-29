# PythonBPF Documentation

This directory contains the Sphinx documentation for PythonBPF.

## Building the Documentation

### Prerequisites

Install the documentation dependencies:

**Using uv (recommended):**
```bash
uv pip install -r requirements.txt
# Or install the optional docs dependencies
uv pip install pythonbpf[docs]
```

**Using pip:**
```bash
pip install -r requirements.txt
# Or install the optional docs dependencies
pip install pythonbpf[docs]
```

### Build HTML Documentation

```bash
make html
```

The generated documentation will be in `_build/html/`. Open `_build/html/index.html` in a browser to view.

### Other Build Formats

```bash
make latexpdf  # Build PDF documentation
make epub      # Build ePub format
make clean     # Clean build artifacts
```

## Documentation Structure

- `index.md` - Main landing page
- `getting-started/` - Installation and quick start guides
- `user-guide/` - Comprehensive user documentation
- `api/` - API reference documentation
- `conf.py` - Sphinx configuration
- `_static/` - Static files (images, CSS, etc.)

## Writing Documentation

Documentation is written in Markdown using [MyST-Parser](https://myst-parser.readthedocs.io/). See the existing files for examples.
