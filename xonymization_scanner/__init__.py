"""Xonymization Scanner - A library for scanning Splunk logs."""

from .client import SplunkClient
from .parser import LogParser
from .scanner import LogScanner
from .raw_parsers import (
    RawFieldParser,
    JsonRawParser,
    PlainTextRawParser,
    KeyValueRawParser,
    RawParserRegistry,
    IndexConfig,
)

__version__ = "0.1.0"
__all__ = [
    "SplunkClient",
    "LogParser",
    "LogScanner",
    "RawFieldParser",
    "JsonRawParser",
    "PlainTextRawParser",
    "KeyValueRawParser",
    "RawParserRegistry",
    "IndexConfig",
]
