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
        help="Disable SSL certificate verification"
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
        default="-24h",
        help="Earliest time for search (default: -24h)"
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
        help="Output format (default: json)"
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
        
        # Initialize scanner
        scanner = LogScanner(client)
        
        # Execute search
        print(f"Executing query: {args.query}", file=sys.stderr)
        if args.index:
            print(f"Index: {args.index}", file=sys.stderr)
        print(f"Time range: {args.earliest} to {args.latest}", file=sys.stderr)
        
        results = scanner.scan(
            query=args.query,
            index=args.index,
            earliest_time=args.earliest,
            latest_time=args.latest,
            max_results=args.max_results,
        )
        
        print(f"Found {len(results)} events", file=sys.stderr)
        
        # Apply filters if specified
        if args.filter_field and args.filter_value:
            print(f"Filtering by {args.filter_field} {args.filter_operator} {args.filter_value}", file=sys.stderr)
            results = scanner.filter_results(
                field=args.filter_field,
                value=args.filter_value,
                operator=args.filter_operator,
            )
            print(f"After filtering: {len(results)} events", file=sys.stderr)
        
        # Generate output
        if args.output_format == "summary":
            summary = scanner.get_summary()
            output = f"""
Summary:
--------
Total Events: {summary['total_events']}
Fields: {', '.join(summary['fields'][:10])}{'...' if len(summary['fields']) > 10 else ''}
Time Range: {summary['time_range']}
"""
            if args.aggregate_by:
                aggregation = scanner.aggregate_results(args.aggregate_by)
                output += f"\nAggregation by '{args.aggregate_by}':\n"
                for key, count in sorted(aggregation.items(), key=lambda x: x[1], reverse=True)[:20]:
                    output += f"  {key}: {count}\n"
        elif args.aggregate_by:
            import json
            aggregation = scanner.aggregate_results(args.aggregate_by)
            output = json.dumps(aggregation, indent=2)
        else:
            output = scanner.export_results(format=args.output_format)
        
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
