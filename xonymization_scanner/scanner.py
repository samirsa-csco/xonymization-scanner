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
