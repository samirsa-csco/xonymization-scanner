"""Tests for the LogParser class."""

import pytest
from xonymization_scanner import LogParser


def test_extract_field():
    """Test basic field extraction."""
    parser = LogParser()
    event = {
        "host": "server1",
        "severity": "error",
        "_raw": "Error message"
    }
    
    assert parser.extract_field(event, "host") == "server1"
    assert parser.extract_field(event, "severity") == "error"
    assert parser.extract_field(event, "nonexistent") is None


def test_extract_nested_field():
    """Test nested field extraction with dot notation."""
    parser = LogParser()
    event = {
        "data": {
            "user": {
                "name": "john"
            }
        }
    }
    
    assert parser.extract_field(event, "data.user.name") == "john"


def test_filter_events():
    """Test event filtering."""
    parser = LogParser()
    events = [
        {"severity": "error", "host": "server1"},
        {"severity": "warning", "host": "server2"},
        {"severity": "error", "host": "server3"},
    ]
    
    # Test equals operator
    filtered = parser.filter_events(events, "severity", "error", "equals")
    assert len(filtered) == 2
    
    # Test contains operator
    filtered = parser.filter_events(events, "host", "server", "contains")
    assert len(filtered) == 3


def test_aggregate_by_field():
    """Test field aggregation."""
    parser = LogParser()
    events = [
        {"host": "server1"},
        {"host": "server2"},
        {"host": "server1"},
        {"host": "server1"},
    ]
    
    aggregation = parser.aggregate_by_field(events, "host")
    assert aggregation["server1"] == 3
    assert aggregation["server2"] == 1


def test_add_pattern():
    """Test adding and using regex patterns."""
    parser = LogParser()
    parser.add_pattern("ip", r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    
    event = {"_raw": "Connection from 192.168.1.100"}
    match = parser.extract_with_pattern(event, "ip", "_raw")
    
    assert match is not None
    assert match["ip"] == "192.168.1.100"


def test_extract_key_value_pairs():
    """Test key-value pair extraction."""
    parser = LogParser()
    event = {"_raw": "user=john status=active count=5"}
    
    pairs = parser.extract_key_value_pairs(event, "_raw")
    assert pairs["user"] == "john"
    assert pairs["status"] == "active"
    assert pairs["count"] == "5"


def test_summarize_events():
    """Test event summarization."""
    parser = LogParser()
    events = [
        {"host": "server1", "severity": "error"},
        {"host": "server2", "severity": "warning"},
    ]
    
    summary = parser.summarize_events(events)
    assert summary["total_events"] == 2
    assert "host" in summary["fields"]
    assert "severity" in summary["fields"]


def test_summarize_empty_events():
    """Test summarization of empty event list."""
    parser = LogParser()
    summary = parser.summarize_events([])
    
    assert summary["total_events"] == 0
    assert summary["fields"] == []
    assert summary["time_range"] is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
