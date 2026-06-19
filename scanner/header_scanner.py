import requests
from urllib.parse import urlparse
from scanner.ssl_scanner import clean_hostname

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version"
]

def scan_http_headers(hostname):
    """
    Sends requests to both http:// and https:// versions of the host,
    and analyzes response headers.
    """
    results = {}
    
    # We test both http and https
    urls_to_test = {
        "http": f"http://{hostname}",
        "https": f"https://{hostname}"
    }
    
    for scheme, url in urls_to_test.items():
        scheme_results = {
            "available": False,
            "redirect_to": None,
            "status_code": None,
            "headers_found": {},
            "missing_security_headers": [],
            "cookie_issues": [],
            "server_disclosure": {}
        }
        
        try:
            # Send standard GET request with redirects disabled first to see actual response
            # Timeout is 5 seconds
            response = requests.get(url, timeout=5, allow_redirects=False, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            scheme_results["available"] = True
            scheme_results["status_code"] = response.status_code
            
            # Check for redirect
            if response.status_code in [301, 302, 307, 308]:
                scheme_results["redirect_to"] = response.headers.get("Location")
            
            # Read all headers
            headers = response.headers
            
            # Assess security headers
            for header in SECURITY_HEADERS:
                if header in headers:
                    scheme_results["headers_found"][header] = headers[header]
                else:
                    scheme_results["missing_security_headers"].append(header)
            
            # Assess disclosure headers
            for header in DISCLOSURE_HEADERS:
                if header in headers:
                    scheme_results["server_disclosure"][header] = headers[header]
            
            # Check Set-Cookie flags
            if "Set-Cookie" in headers:
                cookies = response.headers.getlist("Set-Cookie") if hasattr(response.headers, "getlist") else [headers["Set-Cookie"]]
                for cookie in cookies:
                    cookie_lower = cookie.lower()
                    cookie_name = cookie.split("=")[0] if "=" in cookie else "unknown"
                    
                    issues = []
                    if "httponly" not in cookie_lower:
                        issues.append("HttpOnly flag missing")
                    if "secure" not in cookie_lower:
                        issues.append("Secure flag missing")
                    if "samesite" not in cookie_lower:
                        issues.append("SameSite flag missing")
                        
                    if issues:
                        scheme_results["cookie_issues"].append({
                            "cookie": cookie_name,
                            "issues": issues
                        })
            
            results[scheme] = scheme_results
            
        except requests.exceptions.RequestException as e:
            scheme_results["error"] = str(e)
            results[scheme] = scheme_results
            
    return results

def run_header_scan(target):
    """
    Cleans target hostname and executes the headers scan.
    """
    hostname = clean_hostname(target)
    print(f"[*] Iniciando varredura de cabeçalhos HTTP para {hostname}...")
    
    header_info = scan_http_headers(hostname)
    
    return {
        "hostname": hostname,
        "headers_scan": header_info
    }
