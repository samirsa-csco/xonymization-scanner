#!/usr/bin/env python3
"""Example script demonstrating basic usage of the xonymization_scanner library."""

import os
from xonymization_scanner import SplunkClient, LogScanner, LogParser


def example_basic_search():
    """Example: Basic search and summary."""
    print("=" * 60)
    print("Example 1: Basic Search and Summary")
    print("=" * 60)
    
    # Initialize client (using environment variables for credentials)
    client = SplunkClient(
        host=os.environ.get("SPLUNK_HOST", "splunk.example.com"),
        username=os.environ.get("SPLUNK_USERNAME"),
        password=os.environ.get("SPLUNK_PASSWORD"),
        verify_ssl=False  # Set to True in production
    )
    
    # Test connection
    if not client.test_connection():
        print("Failed to connect to Splunk server")
        return
    
    print("✓ Connected to Splunk successfully\n")
    
    # Create scanner
    scanner = LogScanner(client)
    
    # Execute search
    results = scanner.scan(
        query="error OR warning",
        index="main",
        earliest_time="-1h",
        max_results=100
    )
    
    print(f"Found {len(results)} events\n")
    
    # Get summary
    summary = scanner.get_summary()
    print("Summary:")
    print(f"  Total events: {summary['total_events']}")
    print(f"  Fields: {', '.join(summary['fields'][:5])}...")
    print(f"  Time range: {summary['time_range']}\n")


def example_filtering_and_aggregation():
    """Example: Filtering and aggregation."""
    print("=" * 60)
    print("Example 2: Filtering and Aggregation")
    print("=" * 60)
    
    client = SplunkClient(
        host=os.environ.get("SPLUNK_HOST", "splunk.example.com"),
        token=os.environ.get("SPLUNK_TOKEN"),
        verify_ssl=False
    )
    
    scanner = LogScanner(client)
    
    # Search
    results = scanner.scan(
        query="*",
        index="main",
        earliest_time="-24h",
        max_results=500
    )
    
    print(f"Initial results: {len(results)} events\n")
    
    # Filter by severity
    filtered = scanner.filter_results(
        field="severity",
        value="error",
        operator="equals"
    )
    
    print(f"After filtering by severity=error: {len(filtered)} events\n")
    
    # Aggregate by host
    aggregation = scanner.aggregate_results("host")
    print("Events by host:")
    for host, count in sorted(aggregation.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {host}: {count} events")
    print()


def example_custom_parsing():
    """Example: Custom pattern extraction."""
    print("=" * 60)
    print("Example 3: Custom Pattern Extraction")
    print("=" * 60)
    
    client = SplunkClient(
        host=os.environ.get("SPLUNK_HOST", "splunk.example.com"),
        username=os.environ.get("SPLUNK_USERNAME"),
        password=os.environ.get("SPLUNK_PASSWORD"),
        verify_ssl=False
    )
    
    parser = LogParser()
    scanner = LogScanner(client, parser)
    
    # Add custom patterns
    scanner.add_extraction_pattern(
        "ip_address",
        r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )
    scanner.add_extraction_pattern(
        "error_code",
        r"ERROR_CODE=(?P<code>\d+)"
    )
    
    # Search
    results = scanner.scan(
        query="error",
        index="main",
        earliest_time="-1h",
        max_results=50
    )
    
    print(f"Found {len(results)} events\n")
    
    # Extract IP addresses
    print("Extracting IP addresses from first 5 events:")
    for i, result in enumerate(results[:5]):
        ip_match = parser.extract_with_pattern(result, "ip_address", "_raw")
        if ip_match:
            print(f"  Event {i+1}: {ip_match.get('ip', 'N/A')}")
    print()


def example_export():
    """Example: Export results to different formats."""
    print("=" * 60)
    print("Example 4: Export Results")
    print("=" * 60)
    
    client = SplunkClient(
        host=os.environ.get("SPLUNK_HOST", "splunk.example.com"),
        token=os.environ.get("SPLUNK_TOKEN"),
        verify_ssl=False
    )
    
    scanner = LogScanner(client)
    
    # Search
    results = scanner.scan(
        query="*",
        index="main",
        earliest_time="-1h",
        max_results=10
    )
    
    print(f"Found {len(results)} events\n")
    
    # Export to JSON
    json_output = scanner.export_results(format="json")
    print("JSON export (first 200 chars):")
    print(json_output[:200] + "...\n")
    
    # Export to CSV
    csv_output = scanner.export_results(format="csv")
    print("CSV export (first 200 chars):")
    print(csv_output[:200] + "...\n")


def example_parser_only():
    """Example: Using the parser without Splunk connection."""
    print("=" * 60)
    print("Example 5: Using Parser Standalone")
    print("=" * 60)
    
    parser = LogParser()
    
    # Sample log events
    events = [
        {
            "_raw": "2024-01-15 10:30:45 ERROR: Connection timeout to 192.168.1.100",
            "_time": "1705318245",
            "host": "server1",
            "severity": "error"
        },
        {
            "_raw": "2024-01-15 10:31:12 WARNING: High memory usage detected",
            "_time": "1705318272",
            "host": "server2",
            "severity": "warning"
        },
        {
            "_raw": "2024-01-15 10:32:05 ERROR: Database connection failed",
            "_time": "1705318325",
            "host": "server1",
            "severity": "error"
        }
    ]
    
    print(f"Processing {len(events)} sample events\n")
    
    # Extract fields
    print("Extracting severity field:")
    for event in events:
        severity = parser.extract_field(event, "severity")
        print(f"  {severity}")
    print()
    
    # Filter events
    error_events = parser.filter_events(events, "severity", "error", "equals")
    print(f"Events with severity=error: {len(error_events)}\n")
    
    # Aggregate by host
    aggregation = parser.aggregate_by_field(events, "host")
    print("Events by host:")
    for host, count in aggregation.items():
        print(f"  {host}: {count} events")
    print()
    
    # Parse timestamps
    print("Parsing timestamps:")
    for event in events:
        timestamp = parser.parse_timestamp(event)
        if timestamp:
            print(f"  {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print()


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("Xonymization Scanner - Library Usage Examples")
    print("=" * 60 + "\n")
    
    # Check for required environment variables
    if not os.environ.get("SPLUNK_HOST"):
        print("Note: SPLUNK_HOST environment variable not set.")
        print("Some examples require Splunk connection.\n")
    
    # Run standalone example (doesn't require Splunk)
    example_parser_only()
    
    # Uncomment these to run examples that require Splunk connection:
    # example_basic_search()
    # example_filtering_and_aggregation()
    # example_custom_parsing()
    # example_export()
    
    print("=" * 60)
    print("Examples completed!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
