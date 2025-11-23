#!/usr/bin/env python3
"""Example demonstrating how to use and extend raw field parsers."""

import os
from xonymization_scanner import (
    SplunkClient,
    LogScanner,
    RawParserRegistry,
    RawFieldParser,
)


def example_builtin_parsers():
    """Example: Using built-in parsers."""
    print("=" * 60)
    print("Example 1: Built-in Parsers")
    print("=" * 60)
    
    registry = RawParserRegistry()
    
    # JSON parser (default)
    json_raw = '{"user": "john", "action": "login", "status": "success"}'
    parsed_json = registry.parse(json_raw, "json")
    print(f"JSON parsed: {parsed_json}")
    
    # Key-value parser
    kv_raw = "user=john action=login status=success timestamp=2024-01-15"
    parsed_kv = registry.parse(kv_raw, "keyvalue")
    print(f"Key-value parsed: {parsed_kv}")
    
    # Plain text parser
    text_raw = "2024-01-15 10:30:45 ERROR: Connection timeout"
    parsed_text = registry.parse(text_raw, "plaintext")
    print(f"Plain text: {parsed_text}\n")


def example_custom_parser():
    """Example: Creating a custom parser."""
    print("=" * 60)
    print("Example 2: Custom Parser")
    print("=" * 60)
    
    # Define a custom parser for CSV-like data
    class CsvRawParser(RawFieldParser):
        """Parser for CSV-formatted _raw fields."""
        
        def __init__(self, headers=None, delimiter=","):
            self.headers = headers
            self.delimiter = delimiter
        
        def parse(self, raw_content: str):
            """Parse CSV content."""
            values = raw_content.split(self.delimiter)
            
            if self.headers:
                return dict(zip(self.headers, values))
            else:
                return values
    
    # Register the custom parser
    registry = RawParserRegistry()
    csv_parser = CsvRawParser(headers=["timestamp", "user", "action", "status"])
    registry.register_parser("csv", csv_parser)
    
    # Use the custom parser
    csv_raw = "2024-01-15 10:30:45,john,login,success"
    parsed_csv = registry.parse(csv_raw, "csv")
    print(f"CSV parsed: {parsed_csv}\n")


def example_with_splunk():
    """Example: Using parsers with Splunk search results."""
    print("=" * 60)
    print("Example 3: Parsing Splunk Results")
    print("=" * 60)
    
    # Initialize client
    client = SplunkClient(
        host=os.environ.get("SPLUNK_HOST", "splunk.example.com"),
        username=os.environ.get("SPLUNK_USERNAME"),
        password=os.environ.get("SPLUNK_PASSWORD"),
        verify_ssl=False
    )
    
    # Create scanner
    scanner = LogScanner(client)
    
    # Execute search
    results = scanner.scan(
        query="*",
        index="main",
        earliest_time="-1h",
        max_results=10
    )
    
    print(f"Found {len(results)} events\n")
    
    # Parse _raw fields
    registry = RawParserRegistry()
    
    for i, event in enumerate(results[:3]):
        print(f"Event {i+1}:")
        if "_raw" in event:
            # Try to parse as JSON
            parsed = registry.parse(event["_raw"], "json")
            if parsed:
                print(f"  Parsed JSON: {parsed}")
            else:
                print(f"  Raw text: {event['_raw'][:100]}...")
        print()


def example_xml_parser():
    """Example: Custom XML parser."""
    print("=" * 60)
    print("Example 4: XML Parser")
    print("=" * 60)
    
    import xml.etree.ElementTree as ET
    
    class XmlRawParser(RawFieldParser):
        """Parser for XML-formatted _raw fields."""
        
        def parse(self, raw_content: str):
            """Parse XML content."""
            try:
                root = ET.fromstring(raw_content)
                result = {"tag": root.tag, "attributes": root.attrib}
                
                # Extract text content
                if root.text and root.text.strip():
                    result["text"] = root.text.strip()
                
                # Extract child elements
                children = {}
                for child in root:
                    children[child.tag] = {
                        "text": child.text,
                        "attributes": child.attrib
                    }
                
                if children:
                    result["children"] = children
                
                return result
            except ET.ParseError:
                return None
    
    # Register and use XML parser
    registry = RawParserRegistry()
    registry.register_parser("xml", XmlRawParser())
    
    xml_raw = '<event><user id="123">john</user><action>login</action></event>'
    parsed_xml = registry.parse(xml_raw, "xml")
    print(f"XML parsed: {parsed_xml}\n")


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("Raw Field Parser Examples")
    print("=" * 60 + "\n")
    
    # Run examples that don't require Splunk
    example_builtin_parsers()
    example_custom_parser()
    example_xml_parser()
    
    # Uncomment to run Splunk example:
    # example_with_splunk()
    
    print("=" * 60)
    print("Examples completed!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
