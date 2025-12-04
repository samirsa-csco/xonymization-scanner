# Transaction Grouping Feature

## Overview

The transaction grouping feature allows you to group related log entries by a transaction ID field and view all unique fields across those logs, with nested JSON attributes displayed using dot notation (e.g., `a.b.c = value`).

## Usage

### Basic Transaction Grouping

```bash
uv run python main.py \
  --username USER \
  --password PASS \
  --no-verify-ssl \
  --index "my-index" \
  --query 'sourcetype="oracle-server"' \
  --group-by-transaction
```

This will group logs by the default transaction field `serviceChainId`.

### Custom Transaction Field

```bash
uv run python main.py \
  --username USER \
  --password PASS \
  --no-verify-ssl \
  --index "my-index" \
  --query 'sourcetype="oracle-server"' \
  --transaction-id "requestId" \
  --group-by-transaction
```

This groups logs by a custom field named `requestId`.

### With Filtering

```bash
uv run python main.py \
  --username USER \
  --password PASS \
  --no-verify-ssl \
  --index "my-index" \
  --query 'sourcetype="oracle-server"' \
  --filter-field "status" \
  --filter-value "error" \
  --transaction-id "serviceChainId" \
  --group-by-transaction
```

This filters for error logs first, then groups them by transaction.

## Output Format

For each transaction, the output shows:

1. **Transaction Header**: Transaction ID and number of logs
2. **Individual Logs**: Each log with all fields (nested fields shown with dot notation)
3. **Summary**: All unique fields across the transaction with their values

### Example Output

```
================================================================================
Transaction ID: abc-123-def-456
Number of logs: 3
================================================================================

Log #1:
----------------------------------------
  environment = dev-ssaklika
  request.headers.content-type = application/json
  request.headers.user-agent = Mozilla/5.0
  request.method = POST
  request.path = /api/v1/users
  serviceChainId = abc-123-def-456
  status = 200
  timestamp = 2024-01-15T10:30:45Z

Log #2:
----------------------------------------
  database.query = SELECT * FROM users
  database.duration_ms = 45
  environment = dev-ssaklika
  serviceChainId = abc-123-def-456
  status = 200
  timestamp = 2024-01-15T10:30:45.123Z

Log #3:
----------------------------------------
  environment = dev-ssaklika
  response.body.userId = 12345
  response.body.username = john_doe
  response.status = 200
  serviceChainId = abc-123-def-456
  timestamp = 2024-01-15T10:30:45.456Z

================================================================================
Summary - Unique fields across all logs in transaction abc-123-def-456:
================================================================================
  database.duration_ms = 45
  database.query = SELECT * FROM users
  environment = dev-ssaklika
  request.headers.content-type = application/json
  request.headers.user-agent = Mozilla/5.0
  request.method = POST
  request.path = /api/v1/users
  response.body.userId = 12345
  response.body.username = john_doe
  response.status = 200
  serviceChainId = abc-123-def-456
  status = 2 unique values: ['200', '200']...
  timestamp = 3 unique values: ['2024-01-15T10:30:45Z', '2024-01-15T10:30:45.123Z', '2024-01-15T10:30:45.456Z']...
```

## Nested Field Handling

The feature automatically flattens nested JSON structures:

**Original JSON:**
```json
{
  "user": {
    "profile": {
      "name": "John",
      "age": 30
    }
  }
}
```

**Displayed as:**
```
user.profile.name = John
user.profile.age = 30
```

## Array Handling

Arrays are indexed:

**Original JSON:**
```json
{
  "tags": ["error", "critical", "database"]
}
```

**Displayed as:**
```
tags[0] = error
tags[1] = critical
tags[2] = database
```

## Programmatic Usage

You can also use this feature programmatically:

```python
from xonymization_scanner import SplunkClient, LogScanner

client = SplunkClient(host="splunk.example.com", username="user", password="pass")
scanner = LogScanner(client, raw_format="json")

# Scan and parse
results = scanner.scan(query="*", index="main", parse_raw=True)

# Group by transaction
transactions = scanner.group_by_transaction("serviceChainId")

# Format each transaction
for transaction_id, logs in transactions.items():
    formatted = scanner.format_transaction_group(transaction_id, logs)
    print(formatted)
```

## Use Cases

1. **Debugging distributed systems**: Track a request across multiple services
2. **Performance analysis**: See all operations within a single transaction
3. **Error investigation**: View all logs related to a failed transaction
4. **Audit trails**: Follow a user action through the entire system
