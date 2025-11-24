"""High-level scanner combining client and parser functionality."""

from typing import Any, Dict, List, Optional, Callable
from collections import Counter
import json
import csv
import io
from .client import SplunkClient
from .parser import LogParser
from .raw_parsers import RawParserRegistry


class LogScanner:
    """High-level interface for scanning and analyzing Splunk logs."""

    def __init__(self, client: SplunkClient, parser: Optional[LogParser] = None, raw_format: str = "json"):
        """
        Initialize the log scanner.

        Args:
            client: Configured SplunkClient instance
            parser: LogParser instance (creates new one if not provided)
            raw_format: Format of _raw field (json, plaintext, keyvalue)
        """
        self.client = client
        self.parser = parser or LogParser()
        self.raw_parser_registry = RawParserRegistry()
        self.raw_format = raw_format
        self.results: List[Any] = []
        self.raw_results: List[Dict[str, Any]] = []  # Store original Splunk results

    def scan(
        self,
        query: str,
        index: Optional[str] = None,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int = 1000,
        parse_raw: bool = True,
    ) -> List[Any]:
        """
        Execute a scan on Splunk logs.

        Args:
            query: SPL query string
            index: Splunk index to search
            earliest_time: Earliest time for search
            latest_time: Latest time for search
            max_results: Maximum number of results
            parse_raw: If True, parse _raw field and return only parsed content

        Returns:
            List of parsed _raw content (if parse_raw=True) or full log events
        """
        self.raw_results = self.client.search(
            query=query,
            index=index,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )
        
        if parse_raw:
            self.results = self._parse_raw_fields(self.raw_results)
        else:
            self.results = self.raw_results
        
        return self.results
    
    def _parse_raw_fields(self, events: List[Dict[str, Any]]) -> List[Any]:
        """
        Parse _raw fields from events and return only the parsed content.
        
        Args:
            events: List of Splunk events
            
        Returns:
            List of parsed _raw content
        """
        parsed_results = []
        for event in events:
            if "_raw" in event:
                parsed_raw = self.raw_parser_registry.parse(event["_raw"], self.raw_format)
                if parsed_raw is not None:
                    parsed_results.append(parsed_raw)
                else:
                    # If parsing fails, include the raw text
                    parsed_results.append(event["_raw"])
            else:
                # If no _raw field, include the whole event
                parsed_results.append(event)
        return parsed_results

    def filter_results(
        self, field: str, value: Any, operator: str = "equals"
    ) -> List[Any]:
        """
        Filter the current results (works on dict-like parsed content).

        Args:
            field: Field to filter on
            value: Value to compare against
            operator: Comparison operator

        Returns:
            Filtered list of results
        """
        filtered = []
        for item in self.results:
            if isinstance(item, dict):
                # Use the parser's filter logic
                temp_results = self.parser.filter_events([item], field, value, operator)
                filtered.extend(temp_results)
        self.results = filtered
        return self.results

    def extract_field_from_results(self, field: str) -> List[Optional[str]]:
        """
        Extract a specific field from all results.

        Args:
            field: Field name to extract

        Returns:
            List of field values
        """
        return [self.parser.extract_field(event, field) for event in self.results]

    def aggregate_results(self, field: str) -> Dict[str, int]:
        """
        Aggregate results by field value (works on dict-like parsed content).

        Args:
            field: Field to aggregate by

        Returns:
            Dictionary mapping field values to counts
        """
        if not self.results or not isinstance(self.results[0], dict):
            return {}
        
        field_values = [
            item.get(field) 
            for item in self.results 
            if isinstance(item, dict) and field in item
        ]
        return dict(Counter(field_values))

    def apply_pattern(
        self, pattern_name: str, field: str = "_raw"
    ) -> List[Optional[Dict[str, str]]]:
        """
        Apply a regex pattern to all results.

        Args:
            pattern_name: Name of the pattern to use
            field: Field to apply pattern to

        Returns:
            List of extracted matches
        """
        return [
            self.parser.extract_with_pattern(event, pattern_name, field)
            for event in self.results
        ]

    def add_extraction_pattern(self, name: str, pattern: str) -> None:
        """
        Add a regex pattern for extraction.

        Args:
            name: Pattern name
            pattern: Regex pattern string
        """
        self.parser.add_pattern(name, pattern)

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics for current results.

        Returns:
            Dictionary containing summary information
        """
        return self.parser.summarize_events(self.results)

    def process_results(
        self, processor: Callable[[Dict[str, Any]], Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Apply a custom processing function to all results.

        Args:
            processor: Function that takes an event dict and returns processed event

        Returns:
            List of processed events
        """
        self.results = [processor(event) for event in self.results]
        return self.results

    def export_results(self, format: str = "json", aggregate_by: Optional[str] = None) -> str:
        """
        Export results in specified format.

        Args:
            format: Export format (json, csv, summary)
            aggregate_by: Optional field to aggregate by

        Returns:
            Formatted string of results
        """
        # Handle aggregation
        if aggregate_by:
            aggregation = self.aggregate_results(aggregate_by)
            if format == "summary":
                output = f"""
Summary:
--------
Total Events: {len(self.results)}

Aggregation by '{aggregate_by}':
"""
                for key, count in Counter(aggregation).most_common(20):
                    output += f"  {key}: {count}\n"
                return output
            else:
                return json.dumps(aggregation, indent=2)
        
        # Regular export
        if format == "json":
            return json.dumps(self.results, indent=2, default=str)
        elif format == "csv":
            if not self.results:
                return ""
            
            # CSV only works with dict-like results
            if not isinstance(self.results[0], dict):
                raise ValueError("CSV export requires dict-like results")
            
            output = io.StringIO()
            
            # Get all unique fields
            fields = set()
            for item in self.results:
                if isinstance(item, dict):
                    fields.update(item.keys())
            
            fieldnames = sorted(list(fields))
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for item in self.results:
                if isinstance(item, dict):
                    writer.writerow(item)
            
            return output.getvalue()
        elif format == "summary":
            output = f"""
Summary:
--------
Total Events: {len(self.results)}
"""
            return output
        else:
            raise ValueError(f"Unsupported format: {format}")

    def clear_results(self) -> None:
        """Clear the current results."""
        self.results = []

    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get the current results.

        Returns:
            List of log events
        """
        return self.results

    def count_results(self) -> int:
        """
        Get the count of current results.

        Returns:
            Number of results
        """
        return len(self.results)
    
    def _detect_pii(self, value: Any) -> str:
        """
        Detect if a value is potentially PII (Personally Identifiable Information).
        
        Args:
            value: Value to check
            
        Returns:
            'pii' if potentially PII, 'none' otherwise
        """
        import re
        
        if value is None:
            return 'none'
        
        value_str = str(value)
        
        # IP address pattern (IPv4)
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, value_str):
            parts = value_str.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return 'pii'
        
        # Domain name pattern (basic check for domain-like strings)
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(domain_pattern, value_str):
            return 'pii'
        
        # Email pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, value_str):
            return 'pii'
        
        return 'none'
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """
        Flatten a nested dictionary with dot notation.
        
        Args:
            d: Dictionary to flatten
            parent_key: Parent key for recursion
            sep: Separator for nested keys
            
        Returns:
            Flattened dictionary
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # For lists, create indexed keys
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        items.extend(self._flatten_dict(item, f"{new_key}[{i}]", sep=sep).items())
                    else:
                        items.append((f"{new_key}[{i}]", item))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def group_by_transaction(self, transaction_field: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group results by transaction ID field.
        
        Args:
            transaction_field: Name of the field to group by
            
        Returns:
            Dictionary mapping transaction IDs to lists of log entries
        """
        transactions = {}
        
        for item in self.results:
            if isinstance(item, dict):
                # Get transaction ID from the item
                transaction_id = item.get(transaction_field)
                
                if transaction_id is not None:
                    if transaction_id not in transactions:
                        transactions[transaction_id] = []
                    transactions[transaction_id].append(item)
        
        return transactions
    
    def find_shared_values(self, transaction_logs: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[str]]]:
        """
        Find which fields share the same values within a transaction.
        
        Args:
            transaction_logs: List of log entries for a transaction
            
        Returns:
            Dictionary mapping field names to their values, and for each value,
            a list of other fields that share that value
            Format: {field_name: {value: [other_fields_with_same_value]}}
        """
        # First, collect all field-value pairs
        value_to_fields = {}  # value -> list of fields that have this value
        field_values = {}  # field -> list of its values
        
        for log in transaction_logs:
            flattened = self._flatten_dict(log)
            for field, value in flattened.items():
                value_str = str(value)
                
                # Track which fields have which values
                if value_str not in value_to_fields:
                    value_to_fields[value_str] = set()
                value_to_fields[value_str].add(field)
                
                # Track values for each field
                if field not in field_values:
                    field_values[field] = set()
                field_values[field].add(value_str)
        
        # Build the result: for each field's single value, find other fields with same value
        result = {}
        for field, values in field_values.items():
            result[field] = {}
            for value in values:
                # Find other fields that share this value
                other_fields = [f for f in value_to_fields[value] if f != field]
                if other_fields:
                    result[field][value] = sorted(other_fields)
        
        return result
    
    def format_transaction_group(self, transaction_id: str, logs: List[Dict[str, Any]]) -> str:
        """
        Format a transaction group showing all unique fields across logs.
        
        Args:
            transaction_id: The transaction ID
            logs: List of log entries for this transaction
            
        Returns:
            Formatted string representation
        """
        output = []
        output.append(f"\n{'=' * 80}")
        output.append(f"Transaction ID: {transaction_id}")
        output.append(f"Number of logs: {len(logs)}")
        output.append(f"{'=' * 80}\n")
        
        # Collect all unique fields across all logs in this transaction
        all_fields = {}
        
        for i, log in enumerate(logs, 1):
            output.append(f"Log #{i}:")
            output.append("-" * 40)
            
            # Flatten the log to show nested fields with dot notation
            flattened = self._flatten_dict(log)
            
            # Print all fields for this log
            for key, value in sorted(flattened.items()):
                output.append(f"  {key} = {value}")
                
                # Track unique fields
                if key not in all_fields:
                    all_fields[key] = set()
                all_fields[key].add(str(value))
            
            output.append("")
        
        # Summary of unique fields
        output.append(f"{'=' * 80}")
        output.append(f"Summary - Unique fields across all logs in transaction {transaction_id}:")
        output.append(f"{'=' * 80}")
        for key in sorted(all_fields.keys()):
            values = all_fields[key]
            if len(values) == 1:
                output.append(f"  {key} = {list(values)[0]}")
            else:
                output.append(f"  {key} = {len(values)} unique values: {list(values)[:3]}{'...' if len(values) > 3 else ''}")
        
        return "\n".join(output)
