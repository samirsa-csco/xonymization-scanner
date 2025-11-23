#!/usr/bin/env python3
"""Web application for Splunk log scanner with transaction grouping."""

import os
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from xonymization_scanner import SplunkClient, LogScanner

app = Flask(__name__)
CORS(app)

# Store credentials from environment variables
SPLUNK_CONFIG = {
    'host': os.environ.get('SPLUNK_HOST', 'cisco-opendnsbu-sse.splunkcloud.com'),
    'port': int(os.environ.get('SPLUNK_PORT', '8089')),
    'username': os.environ.get('SPLUNK_USERNAME'),
    'password': os.environ.get('SPLUNK_PASSWORD'),
    'token': os.environ.get('SPLUNK_TOKEN'),
    'verify_ssl': os.environ.get('SPLUNK_VERIFY_SSL', 'true').lower() == 'true'
}

def get_splunk_client():
    """Create and return a Splunk client with configured credentials."""
    return SplunkClient(
        host=SPLUNK_CONFIG['host'],
        port=SPLUNK_CONFIG['port'],
        username=SPLUNK_CONFIG['username'],
        password=SPLUNK_CONFIG['password'],
        token=SPLUNK_CONFIG['token'],
        verify_ssl=SPLUNK_CONFIG['verify_ssl']
    )


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/api/indexes', methods=['GET'])
def get_indexes():
    """Get list of available Splunk indexes."""
    try:
        client = get_splunk_client()
        indexes = client.get_indexes()
        return jsonify({'success': True, 'indexes': indexes})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/search', methods=['POST'])
def search():
    """Execute a Splunk search and return results grouped by transaction."""
    try:
        data = request.json
        index = data.get('index')
        query = data.get('query')
        transaction_field = data.get('transaction_field', 'serviceChainId')
        earliest = data.get('earliest', '-15m')
        latest = data.get('latest', 'now')
        max_results = data.get('max_results', 1000)
        
        if not query:
            return jsonify({'success': False, 'error': 'Query is required'}), 400
        
        # Create client and scanner
        client = get_splunk_client()
        scanner = LogScanner(client, raw_format='json')
        
        # Execute search
        results = scanner.scan(
            query=query,
            index=index,
            earliest_time=earliest,
            latest_time=latest,
            max_results=max_results,
            parse_raw=True
        )
        
        # Group by transaction
        transactions = scanner.group_by_transaction(transaction_field)
        
        # Format response
        transaction_list = []
        transaction_details = {}
        
        for transaction_id, logs in transactions.items():
            transaction_list.append({
                'id': str(transaction_id),
                'log_count': len(logs)
            })
            
            # Flatten and collect unique fields for this transaction
            all_fields = {}
            for log in logs:
                flattened = scanner._flatten_dict(log)
                for key, value in flattened.items():
                    if key not in all_fields:
                        all_fields[key] = []
                    if value not in all_fields[key]:
                        all_fields[key].append(value)
            
            # Convert to list format for table display
            fields_list = []
            for key in sorted(all_fields.keys()):
                values = all_fields[key]
                fields_list.append({
                    'field': key,
                    'values': values,
                    'unique_count': len(values)
                })
            
            transaction_details[str(transaction_id)] = {
                'logs': logs,
                'fields': fields_list
            }
        
        return jsonify({
            'success': True,
            'total_results': len(results),
            'transaction_count': len(transactions),
            'transactions': transaction_list,
            'details': transaction_details
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    try:
        client = get_splunk_client()
        connected = client.test_connection()
        return jsonify({
            'success': True,
            'splunk_connected': connected,
            'config': {
                'host': SPLUNK_CONFIG['host'],
                'port': SPLUNK_CONFIG['port']
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    # Check if credentials are configured
    if not SPLUNK_CONFIG['token'] and not (SPLUNK_CONFIG['username'] and SPLUNK_CONFIG['password']):
        print("ERROR: Splunk credentials not configured!")
        print("Please set SPLUNK_USERNAME and SPLUNK_PASSWORD environment variables")
        print("Or set SPLUNK_TOKEN for token-based authentication")
        exit(1)
    
    print(f"Starting Splunk Log Scanner Web UI...")
    print(f"Splunk Host: {SPLUNK_CONFIG['host']}:{SPLUNK_CONFIG['port']}")
    print(f"Access the UI at: http://localhost:5001")
    
    app.run(host='0.0.0.0', port=5001, debug=True)
