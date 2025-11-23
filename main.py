#!/usr/bin/env python3
"""Main program for scanning Splunk logs using the xonymization_scanner library."""

import argparse
import sys
import os
import json
from typing import Optional
from xonymization_scanner import SplunkClient, LogScanner, RawParserRegistry


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
        
        # Parse _raw field and extract only parsed content
        raw_parser_registry = RawParserRegistry()
        parsed_raw_only = []
        for event in results:
            if "_raw" in event:
                parsed_raw = raw_parser_registry.parse(event["_raw"], args.raw_format)
                if parsed_raw is not None:
                    parsed_raw_only.append(parsed_raw)
                else:
                    # If parsing fails, include the raw text
                    parsed_raw_only.append(event["_raw"])
            else:
                # If no _raw field, include the whole event
                parsed_raw_only.append(event)
        
        # Replace results with just the parsed _raw content
        results = parsed_raw_only
        
        # Apply filters if specified (only works if parsed content is dict-like)
        if args.filter_field and args.filter_value:
            print(f"Filtering by {args.filter_field} {args.filter_operator} {args.filter_value}", file=sys.stderr)
            filtered = []
            for item in results:
                if isinstance(item, dict):
                    # Use the parser's filter logic
                    temp_results = scanner.parser.filter_events([item], args.filter_field, args.filter_value, args.filter_operator)
                    filtered.extend(temp_results)
            results = filtered
            print(f"After filtering: {len(results)} events", file=sys.stderr)
        
        # Generate output
        if args.output_format == "summary":
            output = f"""
Summary:
--------
Total Events: {len(results)}
"""
            if args.aggregate_by and results and isinstance(results[0], dict):
                # Aggregate by field in parsed results
                from collections import Counter
                field_values = [item.get(args.aggregate_by) for item in results if isinstance(item, dict) and args.aggregate_by in item]
                aggregation = Counter(field_values)
                output += f"\nAggregation by '{args.aggregate_by}':\n"
                for key, count in aggregation.most_common(20):
                    output += f"  {key}: {count}\n"
        elif args.aggregate_by and results and isinstance(results[0], dict):
            from collections import Counter
            field_values = [item.get(args.aggregate_by) for item in results if isinstance(item, dict) and args.aggregate_by in item]
            aggregation = Counter(field_values)
            output = json.dumps(dict(aggregation), indent=2)
        elif args.output_format == "csv" and results and isinstance(results[0], dict):
            # CSV output for dict results
            import csv
            import io
            output_io = io.StringIO()
            if results:
                fields = set()
                for item in results:
                    if isinstance(item, dict):
                        fields.update(item.keys())
                fieldnames = sorted(list(fields))
                writer = csv.DictWriter(output_io, fieldnames=fieldnames)
                writer.writeheader()
                for item in results:
                    if isinstance(item, dict):
                        writer.writerow(item)
            output = output_io.getvalue()
        else:
            # Default JSON output of parsed _raw content
            output = json.dumps(results, indent=2, default=str)
        
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
