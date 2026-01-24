# Example: SAFE vulnerability scanner (educational only)
def safe_scanner(url):
    """Check for COMMON vulnerabilities (educational)"""
    import requests
    
    # NEVER use on systems you don't own!
    test_cases = {
        'sql_injection': "' OR '1'='1",
        'xss': '<script>alert("XSS")</script>',
        'path_traversal': '../../etc/passwd'
    }
    
    results = {}
    for test_name, payload in test_cases.items():
        try:
            # This is JUST an example - never run without permission
            response = requests.get(f"{url}?input={payload}", timeout=5)
            results[test_name] = analyze_response(response)
        except:
            pass
    
    return results  # Educational results only