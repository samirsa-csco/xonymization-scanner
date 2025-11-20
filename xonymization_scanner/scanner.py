"""High-level scanner combining client and parser functionality."""

from typing import Any, Dict, List, Optional, Callable
from .client import SplunkClient
from .parser import LogParser


class LogScanner:
    """High-level interface for scanning and analyzing Splunk logs."""

    def __init__(self, client: SplunkClient, parser: Optional[LogParser] = None):
        """
        Initialize the log scanner.

        Args:
            client: Configured SplunkClient instance
            parser: LogParser instance (creates new one if not provided)
        """
        self.client = client
        self.parser = parser or LogParser()
        self.results: List[Dict[str, Any]] = []

    def scan(
        self,
        query: str,
        index: Optional[str] = None,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_results: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Execute a scan on Splunk logs.

        Args:
            query: SPL query string
            index: Splunk index to search
            earliest_time: Earliest time for search
            latest_time: Latest time for search
            max_results: Maximum number of results

        Returns:
            List of log events
        """
        self.results = self.client.search(
            query=query,
            index=index,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )
        return self.results

    def filter_results(
        self, field: str, value: Any, operator: str = "equals"
    ) -> List[Dict[str, Any]]:
        """
        Filter the current results.

        Args:
            field: Field to filter on
            value: Value to compare against
            operator: Comparison operator

        Returns:
            Filtered list of events
        """
        self.results = self.parser.filter_events(self.results, field, value, operator)
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
        Aggregate results by field value.

        Args:
            field: Field to aggregate by

        Returns:
            Dictionary mapping field values to counts
        """
        return self.parser.aggregate_by_field(self.results, field)

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

    def export_results(self, format: str = "json") -> str:
        """
        Export results in specified format.

        Args:
            format: Export format (json, csv)

        Returns:
            Formatted string of results
        """
        if format == "json":
            import json
            return json.dumps(self.results, indent=2, default=str)
        elif format == "csv":
            import csv
            import io
            
            if not self.results:
                return ""
            
            output = io.StringIO()
            
            # Get all unique fields
            fields = set()
            for event in self.results:
                fields.update(event.keys())
            
            fieldnames = sorted(list(fields))
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)
            
            return output.getvalue()
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
