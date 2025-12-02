"""Parsers for handling different formats of the _raw field in Splunk events."""

import json
import yaml
import os
import re
from typing import Any, Dict, Optional, Callable, Literal


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


class IndexConfig:
    """Configuration for index-specific parsing."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize index configuration.
        
        Args:
            config_path: Path to YAML config file
        """
        self.config = self._load_config(config_path)
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to config file
            
        Returns:
            Configuration dictionary
        """
        if not config_path:
            # Try default location
            default_path = os.path.join(os.path.dirname(__file__), '../config/index_config.yaml')
            config_path = default_path if os.path.exists(default_path) else None
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception:
                return {}
        
        return {}
    
    def _find_matching_config(self, index: str) -> Optional[Dict[str, Any]]:
        """
        Find matching config for an index (exact match or regex).
        
        Args:
            index: Index name
            
        Returns:
            Index configuration dict or None
        """
        if 'indexes' not in self.config:
            return None
        
        indexes = self.config.get('indexes', {})
        
        # First try exact match
        if index in indexes:
            return indexes[index]
        
        # Then try regex patterns
        for pattern, config in indexes.items():
            if isinstance(config, dict) and config.get('is_regex', False):
                try:
                    if re.match(pattern, index):
                        return config
                except re.error:
                    # Invalid regex pattern, skip
                    continue
        
        return None
    
    def get_field_path(self, index: Optional[str]) -> Optional[str]:
        """
        Get field path for an index.
        
        Args:
            index: Index name
            
        Returns:
            Field path or None
        """
        if not index:
            return None
        
        index_config = self._find_matching_config(index)
        if not index_config:
            return None
        
        return index_config.get('field_path')
    
    def get_log_format(self, index: Optional[str]) -> Literal['json', 'raw']:
        """
        Get log format for an index.
        
        Args:
            index: Index name
            
        Returns:
            Log format ('json' or 'raw')
        """
        if not index:
            return 'json'
        
        index_config = self._find_matching_config(index)
        if not index_config:
            return 'json'
        
        return index_config.get('log_format', 'json')


class JsonRawParser(RawFieldParser):
    """Parser for JSON-serialized _raw fields with index-specific configuration."""
    
    def __init__(self, config: Optional[IndexConfig] = None):
        """
        Initialize JSON parser.
        
        Args:
            config: IndexConfig instance for index-specific parsing
        """
        self.config = config
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """
        Extract value from nested dictionary using dot notation.
        
        Args:
            data: Dictionary to extract value from
            path: Dot-separated path (e.g., "data.payload.log")
            
        Returns:
            Value at path or None if not found
        """
        keys = path.split('.')
        current = data
        
        try:
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return None
            return current
        except (KeyError, TypeError):
            return None
    
    def parse(self, raw_content: str, index: Optional[str] = None) -> Optional[Any]:
        """
        Parse JSON from raw content with optional field extraction.
        
        Args:
            raw_content: JSON string
            index: Index name for index-specific rules
            
        Returns:
            Parsed content or None if parsing fails
        """
        try:
            # Parse the _raw content as JSON
            parsed_data = json.loads(raw_content)
            
            # Get field path from config if available
            field_path = None
            if self.config and index:
                field_path = self.config.get_field_path(index)
            
            # If no field_path or field_path is None, return full parsed data
            if not field_path:
                return parsed_data
            
            # Extract nested field
            nested_content = self._get_nested_value(parsed_data, field_path)
            
            if nested_content is None:
                return None
            
            # If nested content is a JSON string, parse it
            if isinstance(nested_content, str):
                try:
                    return json.loads(nested_content)
                except json.JSONDecodeError:
                    return nested_content
            
            return nested_content
            
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
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the parser registry with default parsers.
        
        Args:
            config_path: Path to config file for index-specific parsing
        """
        self.index_config = IndexConfig(config_path)
        self.parsers: Dict[str, RawFieldParser] = {
            "json": JsonRawParser(self.index_config),
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
    
    def parse(self, raw_content: str, parser_name: Optional[str] = None, index: Optional[str] = None) -> Any:
        """
        Parse raw content using specified or default parser.
        
        Args:
            raw_content: The raw field content
            parser_name: Name of parser to use (uses default if None)
            index: Index name for index-specific parsing rules
            
        Returns:
            Parsed content
        """
        parser = self.get_parser(parser_name)
        # Try to pass index if parser supports it
        if isinstance(parser, JsonRawParser):
            return parser.parse(raw_content, index)
        else:
            return parser.parse(raw_content)
    
    def get_log_format(self, index: Optional[str]) -> Literal['json', 'raw']:
        """
        Get the log format for an index.
        
        Args:
            index: Index name
            
        Returns:
            Log format ('json' or 'raw')
        """
        return self.index_config.get_log_format(index)
    
    def list_parsers(self) -> list[str]:
        """
        List all registered parser names.
        
        Returns:
            List of parser names
        """
        return list(self.parsers.keys())
