## XSS Vulnerability Scanner

A comprehensive tool to detect Cross-Site Scripting (XSS) vulnerabilities.

### Features

- Tests multiple XSS payloads (60+ included)
- Supports GET and POST methods
- Parameter-specific testing
- Website crawling mode
- Custom payload support
- Reflected XSS detection
- DOM-based XSS detection

### Installation

```bash
pip install -r requirements.txt

## Usage

# Test single URL
python xss_scanner.py -u "https://example.com/page?param=test"

# Test specific parameters
python xss_scanner.py -u "https://example.com/page?param1=test&param2=test" -p param1 -p param2

# Test with POST method
python xss_scanner.py -u "https://example.com/form" --method POST

# Crawl website and test all links
python xss_scanner.py -u "https://example.com" --crawl

# Use custom payloads
python xss_scanner.py -u "https://example.com" --payload "<script>console.log('XSS')</script>"

# Use payloads from file
python xss_scanner.py -u "https://example.com" --payload-file custom_payloads.txt

# Test multiple URLs from file
python xss_scanner.py -f urls.txt

## Included Payload Types

- Basic script tags
- Event handlers (onerror, onload, etc.)
- SVG payloads
- Obfuscated payloads
- DOM-based payloads
- Polyglot payloads
- Bypass attempts
```
