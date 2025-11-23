"""Parsers for handling different formats of the _raw field in Splunk events."""

import json
from typing import Any, Dict, Optional, Callable


class RawFieldParser:
    """Base class for parsing _raw field content."""
    
    def parse(self, raw_content: str) -> Any:
        """
        Parse the raw content.
        
        Args:
            raw_content: The raw field content as string
            
        Returns:
            Parsed content in appropriate format
        """
        raise NotImplementedError("Subclasses must implement parse()")


class JsonRawParser(RawFieldParser):
    """Parser for JSON-serialized _raw fields."""
    
    def parse(self, raw_content: str) -> Optional[Dict[str, Any]]:
        """
        Parse JSON from raw content.
        
        Args:
            raw_content: JSON string
            
        Returns:
            Parsed JSON as dictionary, or None if parsing fails
        """
        try:
            return json.loads(raw_content)
        except (json.JSONDecodeError, TypeError):
            return None


class PlainTextRawParser(RawFieldParser):
    """Parser for plain text _raw fields."""
    
    def parse(self, raw_content: str) -> str:
        """
        Return raw content as-is.
        
        Args:
            raw_content: Plain text string
            
        Returns:
            The raw content unchanged
        """
        return raw_content


class KeyValueRawParser(RawFieldParser):
    """Parser for key=value formatted _raw fields."""
    
    def __init__(self, delimiter: str = " ", separator: str = "="):
        """
        Initialize key-value parser.
        
        Args:
            delimiter: Delimiter between key-value pairs (default: space)
            separator: Separator between key and value (default: =)
        """
        self.delimiter = delimiter
        self.separator = separator
    
    def parse(self, raw_content: str) -> Dict[str, str]:
        """
        Parse key=value pairs from raw content.
        
        Args:
            raw_content: String with key=value pairs
            
        Returns:
            Dictionary of parsed key-value pairs
        """
        result = {}
        pairs = raw_content.split(self.delimiter)
        
        for pair in pairs:
            if self.separator in pair:
                key, value = pair.split(self.separator, 1)
                result[key.strip()] = value.strip()
        
        return result


class RawParserRegistry:
    """Registry for managing different raw field parsers."""
    
    def __init__(self):
        """Initialize the parser registry with default parsers."""
        self.parsers: Dict[str, RawFieldParser] = {
            "json": JsonRawParser(),
            "plaintext": PlainTextRawParser(),
            "keyvalue": KeyValueRawParser(),
        }
        self.default_parser = "json"
    
    def register_parser(self, name: str, parser: RawFieldParser) -> None:
        """
        Register a new parser.
        
        Args:
            name: Name to identify the parser
            parser: RawFieldParser instance
        """
        self.parsers[name] = parser
    
    def set_default_parser(self, name: str) -> None:
        """
        Set the default parser.
        
        Args:
            name: Name of the parser to use as default
        """
        if name not in self.parsers:
            raise ValueError(f"Parser '{name}' not registered")
        self.default_parser = name
    
    def get_parser(self, name: Optional[str] = None) -> RawFieldParser:
        """
        Get a parser by name.
        
        Args:
            name: Parser name (uses default if None)
            
        Returns:
            RawFieldParser instance
        """
        parser_name = name or self.default_parser
        if parser_name not in self.parsers:
            raise ValueError(f"Parser '{parser_name}' not registered")
        return self.parsers[parser_name]
    
    def parse(self, raw_content: str, parser_name: Optional[str] = None) -> Any:
        """
        Parse raw content using specified or default parser.
        
        Args:
            raw_content: The raw field content
            parser_name: Name of parser to use (uses default if None)
            
        Returns:
            Parsed content
        """
        parser = self.get_parser(parser_name)
        return parser.parse(raw_content)
    
    def list_parsers(self) -> list[str]:
        """
        List all registered parser names.
        
        Returns:
            List of parser names
        """
        return list(self.parsers.keys())
