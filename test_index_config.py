#!/usr/bin/env python3
"""Test index-specific configuration."""

from xonymization_scanner.raw_parsers import IndexConfig, JsonRawParser, RawParserRegistry

def test_config_loading():
    """Test that config loads correctly."""
    config = IndexConfig()
    print("✓ Config loaded successfully")
    print(f"  Config data: {config.config}")
    print()

def test_field_path_extraction():
    """Test field path extraction."""
    config = IndexConfig()
    
    # Test regex pattern match
    field_path = config.get_field_path('zproxy-zproxy-clap-nonprod-index')
    print(f"Field path for zproxy-zproxy-clap-nonprod-index: {field_path}")
    assert field_path is None, "Should be None for root extraction"
    
    # Test another matching pattern
    field_path = config.get_field_path('zproxy-zproxy-prod-index')
    print(f"Field path for zproxy-zproxy-prod-index (regex match): {field_path}")
    assert field_path is None, "Should match regex pattern"
    
    # Test non-matching pattern
    field_path = config.get_field_path('other-index')
    print(f"Field path for other-index: {field_path}")
    assert field_path is None, "Should be None for unconfigured index"
    
    print("✓ Field path extraction with regex works")
    print()

def test_log_format():
    """Test log format retrieval."""
    config = IndexConfig()
    
    # Test regex pattern match
    log_format = config.get_log_format('zproxy-zproxy-clap-nonprod-index')
    print(f"Log format for zproxy-zproxy-clap-nonprod-index: {log_format}")
    assert log_format == 'json', "Should be 'json'"
    
    # Test another matching pattern
    log_format = config.get_log_format('zproxy-zproxy-dev-index')
    print(f"Log format for zproxy-zproxy-dev-index (regex match): {log_format}")
    assert log_format == 'json', "Should match regex and return 'json'"
    
    # Test unconfigured index (default)
    log_format = config.get_log_format('unknown-index')
    print(f"Log format for unknown-index: {log_format}")
    assert log_format == 'json', "Should default to 'json'"
    
    print("✓ Log format retrieval with regex works")
    print()

def test_parser_with_config():
    """Test parser with configuration."""
    config = IndexConfig()
    parser = JsonRawParser(config)
    
    # Test direct JSON parsing (no field_path)
    raw_content = '{"timestamp": "2023-01-01T12:00:00", "level": "INFO", "message": "Hello"}'
    result = parser.parse(raw_content, index='zproxy-zproxy-clap-nonprod-index')
    print(f"Parsed result: {result}")
    assert result is not None, "Should parse successfully"
    assert result['level'] == 'INFO', "Should have correct data"
    
    print("✓ Parser with config works")
    print()

def test_parser_with_nested_field():
    """Test parser with nested field extraction."""
    config = IndexConfig()
    # Manually add a test config
    config.config = {
        'indexes': {
            'test-nested': {
                'field_path': 'data.log',
                'log_format': 'json'
            }
        }
    }
    
    parser = JsonRawParser(config)
    
    raw_content = '{"timestamp": "2023-01-01", "data": {"log": {"level": "ERROR", "msg": "Failed"}}}'
    result = parser.parse(raw_content, index='test-nested')
    print(f"Nested extraction result: {result}")
    assert result is not None, "Should parse successfully"
    assert result['level'] == 'ERROR', "Should extract nested field"
    
    print("✓ Nested field extraction works")
    print()

def test_parser_with_json_string_field():
    """Test parser with JSON string in field."""
    config = IndexConfig()
    config.config = {
        'indexes': {
            'test-line': {
                'field_path': 'line',
                'log_format': 'raw'
            }
        }
    }
    
    parser = JsonRawParser(config)
    
    raw_content = '{"timestamp": "2023-01-01", "line": "{\\"level\\": \\"WARN\\", \\"code\\": 404}"}'
    result = parser.parse(raw_content, index='test-line')
    print(f"JSON string extraction result: {result}")
    assert result is not None, "Should parse successfully"
    assert result['level'] == 'WARN', "Should parse JSON string"
    
    print("✓ JSON string field extraction works")
    print()

def test_registry():
    """Test RawParserRegistry with config."""
    registry = RawParserRegistry()
    
    # Test parsing with index
    raw_content = '{"timestamp": "2023-01-01T12:00:00", "level": "INFO"}'
    result = registry.parse(raw_content, 'json', 'zproxy-zproxy-clap-nonprod-index')
    print(f"Registry parse result: {result}")
    assert result is not None, "Should parse successfully"
    
    # Test log format retrieval
    log_format = registry.get_log_format('zproxy-zproxy-clap-nonprod-index')
    print(f"Log format from registry: {log_format}")
    assert log_format == 'json', "Should be 'json'"
    
    print("✓ Registry with config works")
    print()

def main():
    print("=" * 60)
    print("Testing Index-Specific Configuration")
    print("=" * 60)
    print()
    
    try:
        test_config_loading()
        test_field_path_extraction()
        test_log_format()
        test_parser_with_config()
        test_parser_with_nested_field()
        test_parser_with_json_string_field()
        test_registry()
        
        print("=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
