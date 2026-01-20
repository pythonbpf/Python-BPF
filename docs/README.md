# PythonBPF Documentation

This directory contains the Sphinx documentation for PythonBPF.

## Building the Documentation

### Prerequisites

Install the documentation dependencies:

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

### MyST Markdown Features

- Standard Markdown syntax
- Directives using `{directive}` syntax
- Cross-references using `{doc}` and `{ref}`
- Admonitions (notes, warnings, tips)
- Code blocks with syntax highlighting

## Contributing

When adding new documentation:

1. Follow the existing structure
2. Use MyST Markdown syntax
3. Include code examples
4. Test the build with `make html`
5. Check for warnings and errors

## Online Documentation

The documentation is automatically built and deployed to GitHub Pages (if configured).
