"""Log parser for processing and analyzing Splunk log events."""

import re
import json
from typing import Any, Dict, List, Optional, Pattern
from datetime import datetime


class LogParser:
    """Parser for analyzing and extracting information from log events."""

    def __init__(self):
        """Initialize the log parser."""
        self.patterns: Dict[str, Pattern] = {}

    def add_pattern(self, name: str, pattern: str, flags: int = 0) -> None:
        """
        Add a regex pattern for extraction.

        Args:
            name: Name identifier for the pattern
            pattern: Regex pattern string
            flags: Regex flags (e.g., re.IGNORECASE)
        """
        self.patterns[name] = re.compile(pattern, flags)

    def extract_field(self, event: Dict[str, Any], field: str) -> Optional[str]:
        """
        Extract a field value from a log event.

        Args:
            event: Log event dictionary
            field: Field name to extract

        Returns:
            Field value or None if not found
        """
        # Handle nested fields with dot notation
        if "." in field:
            parts = field.split(".")
            value = event
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return None
            return str(value) if value is not None else None
        
        return event.get(field)

    def extract_with_pattern(
        self, event: Dict[str, Any], pattern_name: str, field: str = "_raw"
    ) -> Optional[Dict[str, str]]:
        """
        Extract data using a named pattern from a specific field.

        Args:
            event: Log event dictionary
            pattern_name: Name of the pattern to use
            field: Field to apply pattern to (default: _raw)

        Returns:
            Dictionary of matched groups or None
        """
        if pattern_name not in self.patterns:
            raise ValueError(f"Pattern '{pattern_name}' not found")

        field_value = self.extract_field(event, field)
        if not field_value:
            return None

        pattern = self.patterns[pattern_name]
        match = pattern.search(field_value)
        
        if match:
            return match.groupdict() if match.groupdict() else {"match": match.group(0)}
        
        return None

    def parse_timestamp(
        self, event: Dict[str, Any], field: str = "_time"
    ) -> Optional[datetime]:
        """
        Parse timestamp from event.

        Args:
            event: Log event dictionary
            field: Timestamp field name

        Returns:
            Parsed datetime object or None
        """
        timestamp = self.extract_field(event, field)
        if not timestamp:
            return None

        try:
            # Try parsing as Unix timestamp (float)
            return datetime.fromtimestamp(float(timestamp))
        except (ValueError, TypeError):
            pass

        # Try common timestamp formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%b %d %H:%M:%S",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp, fmt)
            except ValueError:
                continue

        return None

    def filter_events(
        self,
        events: List[Dict[str, Any]],
        field: str,
        value: Any,
        operator: str = "equals",
    ) -> List[Dict[str, Any]]:
        """
        Filter events based on field value.

        Args:
            events: List of log events
            field: Field to filter on
            value: Value to compare against
            operator: Comparison operator (equals, contains, regex, gt, lt)

        Returns:
            Filtered list of events
        """
        filtered = []

        for event in events:
            field_value = self.extract_field(event, field)
            if field_value is None:
                continue

            match = False
            if operator == "equals":
                match = str(field_value) == str(value)
            elif operator == "contains":
                match = str(value) in str(field_value)
            elif operator == "regex":
                match = bool(re.search(str(value), str(field_value)))
            elif operator == "gt":
                try:
                    match = float(field_value) > float(value)
                except (ValueError, TypeError):
                    pass
            elif operator == "lt":
                try:
                    match = float(field_value) < float(value)
                except (ValueError, TypeError):
                    pass

            if match:
                filtered.append(event)

        return filtered

    def aggregate_by_field(
        self, events: List[Dict[str, Any]], field: str
    ) -> Dict[str, int]:
        """
        Aggregate events by field value and count occurrences.

        Args:
            events: List of log events
            field: Field to aggregate by

        Returns:
            Dictionary mapping field values to counts
        """
        aggregation: Dict[str, int] = {}

        for event in events:
            value = self.extract_field(event, field)
            if value:
                key = str(value)
                aggregation[key] = aggregation.get(key, 0) + 1

        return aggregation

    def extract_json_field(
        self, event: Dict[str, Any], field: str = "_raw"
    ) -> Optional[Dict[str, Any]]:
        """
        Parse JSON from a field value.

        Args:
            event: Log event dictionary
            field: Field containing JSON data

        Returns:
            Parsed JSON as dictionary or None
        """
        field_value = self.extract_field(event, field)
        if not field_value:
            return None

        try:
            return json.loads(field_value)
        except json.JSONDecodeError:
            return None

    def extract_key_value_pairs(
        self, event: Dict[str, Any], field: str = "_raw", delimiter: str = "="
    ) -> Dict[str, str]:
        """
        Extract key-value pairs from a field.

        Args:
            event: Log event dictionary
            field: Field containing key-value pairs
            delimiter: Delimiter between key and value

        Returns:
            Dictionary of extracted key-value pairs
        """
        field_value = self.extract_field(event, field)
        if not field_value:
            return {}

        pairs = {}
        # Pattern to match key=value or key="value with spaces"
        pattern = rf'(\w+){re.escape(delimiter)}(?:"([^"]*)"|(\S+))'
        
        for match in re.finditer(pattern, field_value):
            key = match.group(1)
            value = match.group(2) if match.group(2) else match.group(3)
            pairs[key] = value

        return pairs

    def summarize_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for a list of events.

        Args:
            events: List of log events

        Returns:
            Dictionary containing summary statistics
        """
        if not events:
            return {
                "total_events": 0,
                "fields": [],
                "time_range": None,
            }

        # Collect all unique fields
        all_fields = set()
        for event in events:
            all_fields.update(event.keys())

        # Get time range
        timestamps = []
        for event in events:
            ts = self.parse_timestamp(event)
            if ts:
                timestamps.append(ts)

        time_range = None
        if timestamps:
            time_range = {
                "earliest": min(timestamps).isoformat(),
                "latest": max(timestamps).isoformat(),
            }

        return {
            "total_events": len(events),
            "fields": sorted(list(all_fields)),
            "time_range": time_range,
        }
