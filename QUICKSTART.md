# Quick Start Guide

## Installation

```bash
# Install dependencies using uv
uv sync

# Install with dev dependencies (for testing)
uv sync --extra dev
```

## Running the CLI

The CLI tool must be run with `uv run` to use the virtual environment:

```bash
# Show help
uv run python main.py --help

# Basic query example
uv run python main.py \
  --host splunk.example.com \
  --username admin \
  --password secret \
  --query "error" \
  --index main

# Using environment variables
export SPLUNK_HOST=splunk.example.com
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=secret

uv run python main.py --host $SPLUNK_HOST --query "error" --index main
```

## Using the Library

### In a Python Script

Create a script and run it with `uv run`:

```python
# my_script.py
from xonymization_scanner import SplunkClient, LogScanner

client = SplunkClient(
    host="splunk.example.com",
    username="admin",
    password="secret"
)

scanner = LogScanner(client)
results = scanner.scan(query="error", index="main")
print(f"Found {len(results)} events")
```

Run it:
```bash
uv run python my_script.py
```

### In Interactive Python

```bash
uv run python
```

```python
>>> from xonymization_scanner import LogParser
>>> parser = LogParser()
>>> event = {"host": "server1", "severity": "error"}
>>> parser.extract_field(event, "host")
'server1'
```

## Running Examples

```bash
# Run the example script
uv run python examples/basic_usage.py
```

## Running Tests

```bash
# Install dev dependencies first
uv sync --extra dev

# Run tests
uv run pytest tests/ -v
```

## Common Use Cases

### 1. Search and Export to CSV

```bash
uv run python main.py \
  --host splunk.example.com \
  --username admin \
  --password secret \
  --query "error" \
  --index main \
  --output-format csv \
  --output-file results.csv
```

### 2. Aggregate Results

```bash
uv run python main.py \
  --host splunk.example.com \
  --token YOUR_TOKEN \
  --query "*" \
  --index main \
  --aggregate-by host
```

### 3. Filter and Summarize

```bash
uv run python main.py \
  --host splunk.example.com \
  --username admin \
  --password secret \
  --query "error" \
  --index main \
  --filter-field severity \
  --filter-value critical \
  --output-format summary
```

### 4. List Available Indexes

```bash
uv run python main.py \
  --host splunk.example.com \
  --username admin \
  --password secret \
  --list-indexes
```

## Project Structure

```
xonymization-scanner/
├── xonymization_scanner/       # Core library
│   ├── __init__.py
│   ├── client.py              # Splunk API client
│   ├── parser.py              # Log parsing utilities
│   └── scanner.py             # High-level scanner
├── main.py                     # CLI application
├── examples/                   # Example scripts
│   └── basic_usage.py
├── tests/                      # Test suite
│   └── test_parser.py
├── pyproject.toml             # Project configuration
├── README.md                  # Full documentation
└── QUICKSTART.md              # This file
```

## Troubleshooting

### ModuleNotFoundError: No module named 'requests'

Always use `uv run` to execute Python scripts:
```bash
uv run python main.py --help
```

### Connection Errors

- Verify Splunk host and port are correct
- Check credentials are valid
- Use `--no-verify-ssl` for self-signed certificates (dev only)
- Test connection with `--list-indexes`

### Import Errors

Make sure dependencies are installed:
```bash
uv sync
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check out [examples/basic_usage.py](examples/basic_usage.py) for more examples
- Review the library code in `xonymization_scanner/` to understand the API
