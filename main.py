#!/usr/bin/env python3
"""Main program for scanning Splunk logs using the xonymization_scanner library."""

import argparse
import sys
import os
from typing import Optional
from xonymization_scanner import SplunkClient, LogScanner


def main():
    """Main entry point for the Splunk log scanner."""
    parser = argparse.ArgumentParser(
        description="Scan Splunk logs for analysis and pattern matching"
    )
    
    # Connection arguments
    parser.add_argument(
        "--host",
        default="cisco-opendnsbu-sse.splunkcloud.com",
        help="Splunk server hostname or IP address (default: cisco-opendnsbu-sse.splunkcloud.com)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8089,
        help="Splunk management port (default: 8089)"
    )
    parser.add_argument(
        "--username",
        help="Splunk username for authentication"
    )
    parser.add_argument(
        "--password",
        help="Splunk password for authentication (use quotes if it contains special characters)"
    )
    parser.add_argument(
        "--token",
        help="Splunk bearer token for authentication (alternative to username/password)"
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification (not recommended for production)"
    )
    
    # Search arguments
    parser.add_argument(
        "--index",
        help="Splunk index to search"
    )
    parser.add_argument(
        "--query",
        required=True,
        help="SPL (Search Processing Language) query"
    )
    parser.add_argument(
        "--earliest",
        default="-15m",
        help="Earliest time for search (default: -15m)"
    )
    parser.add_argument(
        "--latest",
        default="now",
        help="Latest time for search (default: now)"
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=1000,
        help="Maximum number of results to return (default: 1000)"
    )
    
    # Output arguments
    parser.add_argument(
        "--output-format",
        choices=["json", "csv", "summary"],
        default="json",
        help="Output format (default: json). Outputs parsed _raw field content only"
    )
    parser.add_argument(
        "--output-file",
        help="Output file path (default: stdout)"
    )
    
    # Filter arguments
    parser.add_argument(
        "--filter-field",
        help="Field to filter results on"
    )
    parser.add_argument(
        "--filter-value",
        help="Value to filter by"
    )
    parser.add_argument(
        "--filter-operator",
        choices=["equals", "contains", "regex", "gt", "lt"],
        default="equals",
        help="Filter operator (default: equals)"
    )
    
    # Aggregation arguments
    parser.add_argument(
        "--aggregate-by",
        help="Field to aggregate results by (shows counts)"
    )
    
    # Raw field parsing
    parser.add_argument(
        "--raw-format",
        choices=["json", "plaintext", "keyvalue"],
        default="json",
        help="Format of the _raw field (default: json)"
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Output raw Splunk response without parsing (ignores --output-format and --raw-format)"
    )
    
    # Transaction grouping
    parser.add_argument(
        "--transaction-id",
        default="serviceChainID",
        help="Field name to group logs by transaction (default: serviceChainID)"
    )
    parser.add_argument(
        "--group-by-transaction",
        action="store_true",
        help="Group and display logs by transaction ID"
    )
    
    # List indexes
    parser.add_argument(
        "--list-indexes",
        action="store_true",
        help="List available Splunk indexes and exit"
    )
    
    args = parser.parse_args()
    
    # Get credentials from environment if not provided
    username = args.username or os.environ.get("SPLUNK_USERNAME")
    password = args.password or os.environ.get("SPLUNK_PASSWORD")
    token = args.token or os.environ.get("SPLUNK_TOKEN")
    
    if not token and not (username and password):
        print("Error: Either --token or --username/--password must be provided", file=sys.stderr)
        print("Alternatively, set SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD environment variables", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Initialize Splunk client
        client = SplunkClient(
            host=args.host,
            port=args.port,
            username=username,
            password=password,
            token=token,
            verify_ssl=not args.no_verify_ssl,
        )
        
        # Test connection
        print("Connecting to Splunk...", file=sys.stderr)
        if not client.test_connection():
            print("Error: Failed to connect to Splunk server", file=sys.stderr)
            sys.exit(1)
        print("Connected successfully!", file=sys.stderr)
        
        # List indexes if requested
        if args.list_indexes:
            print("\nAvailable indexes:", file=sys.stderr)
            indexes = client.get_indexes()
            for idx in indexes:
                print(f"  - {idx}")
            sys.exit(0)
        
        # Execute search
        print(f"Executing query: {args.query}", file=sys.stderr)
        if args.index:
            print(f"Index: {args.index}", file=sys.stderr)
        print(f"Time range: {args.earliest} to {args.latest}", file=sys.stderr)
        
        # If --raw flag is set, use client.search directly without parsing
        if args.raw:
            results = client.search(
                query=args.query,
                index=args.index,
                earliest_time=args.earliest,
                latest_time=args.latest,
                max_results=args.max_results,
            )
            
            print(f"Found {len(results)} events", file=sys.stderr)
            
            # Output raw JSON response
            import json
            output = json.dumps(results, indent=2)
            
            # Write output
            if args.output_file:
                with open(args.output_file, "w") as f:
                    f.write(output)
                print(f"Results written to {args.output_file}", file=sys.stderr)
            else:
                print(output)
            
            sys.exit(0)
        
        # Initialize scanner with raw format for normal processing
        scanner = LogScanner(client, raw_format=args.raw_format)
        
        results = scanner.scan(
            query=args.query,
            index=args.index,
            earliest_time=args.earliest,
            latest_time=args.latest,
            max_results=args.max_results,
            parse_raw=True,
        )
        
        print(f"Found {len(results)} events", file=sys.stderr)
        
        # Apply filters if specified
        if args.filter_field and args.filter_value:
            print(f"Filtering by {args.filter_field} {args.filter_operator} {args.filter_value}", file=sys.stderr)
            scanner.filter_results(
                field=args.filter_field,
                value=args.filter_value,
                operator=args.filter_operator,
            )
            print(f"After filtering: {len(scanner.results)} events", file=sys.stderr)
        
        # Handle transaction grouping if requested
        if args.group_by_transaction:
            print(f"Grouping by transaction field: {args.transaction_id}", file=sys.stderr)
            transactions = scanner.group_by_transaction(args.transaction_id)
            print(f"Found {len(transactions)} unique transactions", file=sys.stderr)
            
            # Format output for each transaction
            output_parts = []
            for transaction_id, logs in transactions.items():
                formatted = scanner.format_transaction_group(transaction_id, logs)
                output_parts.append(formatted)
            
            output = "\n".join(output_parts)
        else:
            # Generate output using scanner's export method
            output = scanner.export_results(
                format=args.output_format,
                aggregate_by=args.aggregate_by
            )
        
        # Write output
        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(output)
            print(f"Results written to {args.output_file}", file=sys.stderr)
        else:
            print(output)
        
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
