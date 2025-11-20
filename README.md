# Xonymization Scanner

A Python library and CLI tool for scanning and analyzing Splunk logs. This project provides both a reusable library for programmatic access to Splunk logs and a command-line interface for quick queries and analysis.

## Features

- **Splunk Client**: Connect to Splunk servers using username/password or bearer token authentication
- **Log Parser**: Parse and extract information from log events with regex patterns, field extraction, and filtering
- **Log Scanner**: High-level interface combining client and parser functionality
- **CLI Tool**: Command-line interface for quick Splunk queries and analysis
- **Multiple Output Formats**: Export results as JSON, CSV, or summary statistics
- **Filtering & Aggregation**: Filter results by field values and aggregate by specific fields

## Installation

This project uses `uv` for dependency management. To install dependencies:

```bash
# Install dependencies
uv sync

# Or install the package in development mode
uv pip install -e .
```

## Usage

### Command-Line Interface

The main CLI program provides a convenient way to query Splunk logs:

```bash
# Basic query
python main.py --host splunk.example.com --username admin --password secret --query "error" --index main

# Using environment variables for credentials
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=secret
python main.py --host splunk.example.com --query "error" --index main

# Using bearer token
python main.py --host splunk.example.com --token YOUR_TOKEN --query "error" --index main

# List available indexes
python main.py --host splunk.example.com --username admin --password secret --list-indexes

# Query with time range
python main.py --host splunk.example.com --username admin --password secret \
  --query "status=500" --index web_logs \
  --earliest "-7d" --latest "now" \
  --max-results 5000

# Filter results
python main.py --host splunk.example.com --username admin --password secret \
  --query "error" --index main \
  --filter-field severity --filter-value "critical" --filter-operator equals

# Aggregate results
python main.py --host splunk.example.com --username admin --password secret \
  --query "error" --index main \
  --aggregate-by host

# Export to CSV
python main.py --host splunk.example.com --username admin --password secret \
  --query "error" --index main \
  --output-format csv --output-file results.csv

# Get summary statistics
python main.py --host splunk.example.com --username admin --password secret \
  --query "error" --index main \
  --output-format summary
```

### Library Usage

You can also use the library programmatically in your Python code:

#### Basic Example

```python
from xonymization_scanner import SplunkClient, LogScanner

# Initialize client
client = SplunkClient(
    host="splunk.example.com",
    username="admin",
    password="secret",
    verify_ssl=True
)

# Test connection
if client.test_connection():
    print("Connected to Splunk!")

# Create scanner
scanner = LogScanner(client)

# Execute search
results = scanner.scan(
    query="error",
    index="main",
    earliest_time="-24h",
    latest_time="now",
    max_results=1000
)

print(f"Found {len(results)} events")

# Get summary
summary = scanner.get_summary()
print(summary)
```

#### Advanced Example with Filtering and Parsing

```python
from xonymization_scanner import SplunkClient, LogScanner, LogParser

# Initialize
client = SplunkClient(
    host="splunk.example.com",
    token="YOUR_BEARER_TOKEN"
)

parser = LogParser()
scanner = LogScanner(client, parser)

# Add custom regex pattern
scanner.add_extraction_pattern(
    "error_code",
    r"ERROR_CODE=(?P<code>\d+)"
)

# Search and filter
results = scanner.scan(
    query="error",
    index="application_logs",
    earliest_time="-1h"
)

# Filter by field
filtered = scanner.filter_results(
    field="severity",
    value="high",
    operator="equals"
)

# Aggregate by host
aggregation = scanner.aggregate_results("host")
for host, count in aggregation.items():
    print(f"{host}: {count} errors")

# Export results
json_output = scanner.export_results(format="json")
csv_output = scanner.export_results(format="csv")
```

#### Using the Parser Directly

```python
from xonymization_scanner import LogParser

parser = LogParser()

# Extract field from event
event = {
    "_raw": "2024-01-01 ERROR: Connection failed",
    "host": "server1",
    "severity": "high"
}

severity = parser.extract_field(event, "severity")
print(severity)  # "high"

# Add and use regex pattern
parser.add_pattern("timestamp", r"(\d{4}-\d{2}-\d{2})")
match = parser.extract_with_pattern(event, "timestamp", "_raw")
print(match)  # {'0': '2024-01-01'}

# Parse timestamp
timestamp = parser.parse_timestamp(event, "_time")

# Extract key-value pairs
kv_pairs = parser.extract_key_value_pairs(event, "_raw")
```

## Project Structure

```
xonymization-scanner/
├── xonymization_scanner/       # Core library package
│   ├── __init__.py            # Package exports
│   ├── client.py              # Splunk REST API client
│   ├── parser.py              # Log parsing and extraction
│   └── scanner.py             # High-level scanner interface
├── main.py                     # CLI application
├── pyproject.toml             # Project configuration and dependencies
└── README.md                  # This file
```

## Library Components

### SplunkClient

The `SplunkClient` class handles communication with the Splunk REST API:

- **Authentication**: Supports username/password and bearer token authentication
- **Search**: Execute SPL queries and retrieve results
- **Indexes**: List available Splunk indexes
- **Connection Testing**: Verify connectivity to Splunk server

### LogParser

The `LogParser` class provides log parsing and analysis capabilities:

- **Field Extraction**: Extract fields from log events with dot notation support
- **Regex Patterns**: Add and apply custom regex patterns for data extraction
- **Timestamp Parsing**: Parse timestamps in various formats
- **Filtering**: Filter events by field values with multiple operators
- **Aggregation**: Count occurrences by field values
- **Key-Value Extraction**: Parse key=value pairs from log messages
- **JSON Parsing**: Extract and parse JSON from log fields

### LogScanner

The `LogScanner` class combines client and parser functionality:

- **Unified Interface**: Single interface for searching and analyzing logs
- **Result Management**: Store and manipulate search results
- **Export**: Export results in JSON or CSV format
- **Custom Processing**: Apply custom processing functions to results

## Environment Variables

The CLI supports the following environment variables:

- `SPLUNK_USERNAME`: Splunk username for authentication
- `SPLUNK_PASSWORD`: Splunk password for authentication
- `SPLUNK_TOKEN`: Splunk bearer token for authentication

## Requirements

- Python >= 3.10
- requests >= 2.31.0

## Development

This project is managed with `uv`. To set up for development:

```bash
# Clone the repository
git clone <repository-url>
cd xonymization-scanner

# Install dependencies
uv sync

# Run the CLI
python main.py --help

# Use the library in Python
python
>>> from xonymization_scanner import SplunkClient
>>> # Your code here
```

## Security Notes

- Never hardcode credentials in your code
- Use environment variables or secure credential storage
- Consider using bearer tokens instead of username/password
- Be cautious with SSL verification in production environments
- Limit search result sizes to avoid memory issues

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]
