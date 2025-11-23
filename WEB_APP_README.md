# Splunk Transaction Viewer - Web Application

A modern, browser-based UI for viewing and analyzing Splunk logs grouped by transaction ID.

## Features

- 🎨 **Modern UI** - Clean, gradient-based design with smooth animations
- 🔍 **Transaction Grouping** - Automatically groups logs by transaction ID
- 📊 **Field Analysis** - Shows all unique fields with their values
- 🌳 **Nested Field Support** - Displays nested JSON as `a.b.c = value`
- 🔐 **Secure** - Credentials stored server-side, never exposed to browser

## Screenshots

### Main Interface
- **Top Row**: Index selector, Query input, Transaction ID field name
- **Left Panel**: List of all unique transaction IDs with log counts
- **Right Panel**: Detailed field view for selected transaction

## Installation

### 1. Install Dependencies

```bash
# Sync dependencies (includes Flask)
uv sync
```

### 2. Set Environment Variables

The web app requires Splunk credentials to be set as environment variables:

```bash
export SPLUNK_HOST="cisco-opendnsbu-sse.splunkcloud.com"
export SPLUNK_PORT="8089"
export SPLUNK_USERNAME="your-username"
export SPLUNK_PASSWORD="your-password"
export SPLUNK_VERIFY_SSL="false"  # Set to "true" for production
```

Or use token-based authentication:

```bash
export SPLUNK_HOST="cisco-opendnsbu-sse.splunkcloud.com"
export SPLUNK_PORT="8089"
export SPLUNK_TOKEN="your-api-token"
export SPLUNK_VERIFY_SSL="false"
```

### 3. Run the Web Application

```bash
uv run python web_app.py
```

The application will start on `http://localhost:5000`

## Usage

### 1. Enter Search Parameters

- **Index**: Enter the Splunk index name (e.g., `zproxy-zproxy-clap-nonprod-index`)
- **Query**: Enter your SPL query (e.g., `sourcetype="oracle-server" environment="dev"`)
- **Transaction ID Field**: Field name to group by (default: `serviceChainId`)

### 2. Execute Search

Click the **"Search & Group"** button to execute the search. The app will:
1. Query Splunk with your parameters
2. Parse the `_raw` field as JSON
3. Group results by the transaction ID field
4. Display unique transaction IDs in the left panel

### 3. View Transaction Details

Click on any transaction ID in the left panel to view:
- **Transaction ID**: The unique identifier
- **Log Count**: Number of logs in this transaction
- **Field Table**: All unique fields with their values
  - Fields with multiple values are highlighted in yellow
  - Nested fields shown with dot notation (e.g., `request.headers.content-type`)

## API Endpoints

The web app exposes the following REST API endpoints:

### `GET /api/health`
Health check and connection status

**Response:**
```json
{
  "success": true,
  "splunk_connected": true,
  "config": {
    "host": "cisco-opendnsbu-sse.splunkcloud.com",
    "port": 8089
  }
}
```

### `GET /api/indexes`
Get list of available Splunk indexes

**Response:**
```json
{
  "success": true,
  "indexes": ["main", "security", "application"]
}
```

### `POST /api/search`
Execute a search and group by transaction

**Request:**
```json
{
  "index": "main",
  "query": "sourcetype=\"oracle-server\"",
  "transaction_field": "serviceChainId",
  "earliest": "-15m",
  "latest": "now",
  "max_results": 1000
}
```

**Response:**
```json
{
  "success": true,
  "total_results": 150,
  "transaction_count": 25,
  "transactions": [
    {
      "id": "abc-123-def",
      "log_count": 6
    }
  ],
  "details": {
    "abc-123-def": {
      "logs": [...],
      "fields": [
        {
          "field": "request.method",
          "values": ["POST"],
          "unique_count": 1
        }
      ]
    }
  }
}
```

## Deployment

### Production Deployment

For production deployment, consider:

1. **Use a production WSGI server** (e.g., Gunicorn):
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 web_app:app
   ```

2. **Enable HTTPS** with a reverse proxy (nginx, Apache)

3. **Set secure environment variables**:
   ```bash
   export SPLUNK_VERIFY_SSL="true"
   export FLASK_ENV="production"
   ```

4. **Configure CORS** appropriately for your domain

### Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install uv && uv sync

COPY . .

ENV FLASK_ENV=production
EXPOSE 5000

CMD ["python", "web_app.py"]
```

Build and run:
```bash
docker build -t splunk-viewer .
docker run -p 5000:5000 \
  -e SPLUNK_HOST="your-host" \
  -e SPLUNK_USERNAME="user" \
  -e SPLUNK_PASSWORD="pass" \
  splunk-viewer
```

## Security Considerations

1. **Credentials**: Never expose Splunk credentials in the frontend. They are stored server-side only.
2. **SSL**: Always use SSL verification in production (`SPLUNK_VERIFY_SSL=true`)
3. **Authentication**: Consider adding user authentication to the web app
4. **Rate Limiting**: Implement rate limiting for API endpoints
5. **Input Validation**: The app validates all inputs, but review for your use case

## Troubleshooting

### Connection Errors

If you see "Failed to connect to Splunk":
1. Verify environment variables are set correctly
2. Check network connectivity to Splunk host
3. Verify credentials are valid
4. Check SSL settings

### No Transactions Found

If search returns no transactions:
1. Verify the transaction ID field name is correct
2. Check that logs actually contain that field
3. Adjust time range (earliest/latest)
4. Verify the SPL query is correct

### Import Errors

If you see Flask import errors:
```bash
uv sync  # Re-sync dependencies
```

## Customization

### Change Default Port

Edit `web_app.py`:
```python
app.run(host='0.0.0.0', port=8080, debug=True)
```

### Modify UI Colors

Edit `templates/index.html` and change the gradient colors:
```css
background: linear-gradient(135deg, #YOUR_COLOR_1 0%, #YOUR_COLOR_2 100%);
```

### Add Custom Fields

To add more search parameters, update:
1. HTML form in `templates/index.html`
2. API endpoint in `web_app.py`
3. Scanner call parameters

## License

[Add your license here]
