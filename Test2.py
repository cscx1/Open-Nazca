"""
SECURITY VULNERABILITY DEMONSTRATION FILE
FOR EDUCATIONAL PURPOSES ONLY
Contains 15 intentionally created security vulnerabilities
"""

import os
import sys
import pickle
import json
import yaml
import subprocess
import tempfile
import shlex
import sqlite3
import hashlib
import base64
import ctypes
import marshal
import zipfile
import tarfile
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import re
import threading
import datetime
import hashlib
import socket
import logging
from typing import Any, Dict, List, Optional
import inspect
import builtins

# ============ VULNERABILITY 1: Command Injection with shlex.quote bypass ============
def vulnerable_file_operation(filename: str) -> str:
    """
    Command injection vulnerability - attacker can break out of quotes
    Vulnerability: Using shell=True with user input
    Severity: Critical
    """
    # User input goes directly into command
    user_input = filename
    
    # Appears safe but has hidden vulnerability
    safe_looking = shlex.quote(user_input)
    
    # Bypass: If user_input is `'; cat /etc/passwd; '`
    # shlex.quote gives: `''\''; cat /etc/passwd; '\'''`
    # But then we do this:
    command = f"ls -la {safe_looking}"
    
    # Actually vulnerable because of shell=True
    result = subprocess.check_output(command, shell=True)  # VULN: shell=True with user input
    return result.decode('utf-8')


# ============ VULNERABILITY 2: SQL Injection with parameterized query bypass ============
class VulnerableDatabase:
    def __init__(self):
        self.conn = sqlite3.connect(':memory:')
        self.cursor = self.conn.cursor()
        self.cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
        self.cursor.execute("INSERT INTO users VALUES (1, 'admin', 'SUPER_SECRET_123')")
        self.conn.commit()
    
    def get_user_secret(self, user_id: str) -> str:
        """
        SQL injection with clever bypass
        Vulnerability: String formatting in SQL
        Severity: High
        """
        # Looks like parameterized query but isn't
        query = "SELECT secret FROM users WHERE id = %s" % user_id  # VULN: Direct string formatting
        
        # Attack: user_id = "1 OR 1=1 --"
        # Result: SELECT secret FROM users WHERE id = 1 OR 1=1 --
        self.cursor.execute(query)
        result = self.cursor.fetchone()
        return result[0] if result else ""


# ============ VULNERABILITY 3: Deserialization attack with signed pickle ============
class MaliciousPickle:
    def __reduce__(self):
        """
        Pickle deserialization RCE payload
        """
        import os
        return (os.system, ('echo "PWNED" > /tmp/hacked',))


def vulnerable_deserialization(data: bytes, secret_key: str) -> Any:
    """
    Pickle deserialization RCE
    Vulnerability: Unsafe deserialization
    Severity: Critical
    """
    # Appears to check signature first
    signature = data[:32]
    payload = data[32:]
    
    # "Verify" signature (but implementation is flawed)
    expected_sig = hashlib.md5(payload + secret_key.encode()).digest()
    
    if signature == expected_sig:
        # VULN: Deserializing untrusted data
        obj = pickle.loads(payload)  # VULN: Arbitrary code execution
        return obj
    return None


# ============ VULNERABILITY 4: XXE in XML parsing ============
def vulnerable_xml_parser(xml_data: str) -> Dict:
    """
    XXE vulnerability
    Vulnerability: External entity expansion
    Severity: High
    """
    # Disable DTD loading (but not completely)
    parser = ET.XMLParser()
    
    # Parse XML
    root = ET.fromstring(xml_data, parser=parser)  # VULN: XXE if DTD not fully disabled
    
    # Attack payload:
    # <?xml version="1.0"?>
    # <!DOCTYPE foo [
    #   <!ENTITY xxe SYSTEM "file:///etc/passwd">
    # ]>
    # <root>&xxe;</root>
    
    result = {}
    for child in root:
        result[child.tag] = child.text
    return result


# ============ VULNERABILITY 5: Path traversal with Unicode normalization bypass ============
def vulnerable_file_read(filepath: str) -> str:
    """
    Path traversal with Unicode bypass
    Vulnerability: Inadequate path sanitization
    Severity: High
    """
    base_dir = "/safe/directory"
    
    # Attempt to prevent directory traversal
    if ".." in filepath:
        raise ValueError("Directory traversal not allowed")
    
    # Join paths
    full_path = os.path.join(base_dir, filepath)
    
    # Check if path is within base directory
    if not os.path.commonpath([base_dir, full_path]) == base_dir:
        raise ValueError("Access denied")
    
    # VULN: Unicode normalization attack
    # Attack: filepath = "..%u2216..%u2216etc%u2216passwd" (Unicode backslash)
    # Normalization might not catch this
    
    with open(full_path, 'r') as f:  # VULN: Path traversal
        return f.read()


# ============ VULNERABILITY 6: Template injection with Python code execution ============
def vulnerable_template_render(template: str, context: Dict) -> str:
    """
    Template injection/SSTI
    Vulnerability: Executing user input as Python
    Severity: Critical
    """
    # Simple "template engine" that's actually dangerous
    for key, value in context.items():
        template = template.replace(f"{{{{ {key} }}}}", str(value))
    
    # VULN: Allows Python code execution in templates
    # Attack: template = "{{ __import__('os').system('id') }}"
    
    # Even worse: Allow arbitrary Python execution
    if "__" in template:  # Weak attempt to block dunders
        raise ValueError("Invalid template")
    
    # Actually execute Python code in template
    try:
        # Use eval to "render" expressions
        result = eval(template, {"__builtins__": {}}, context)  # VULN: Code execution
        return str(result)
    except:
        return template


# ============ VULNERABILITY 7: Unsafe reflection/import ============
def vulnerable_dynamic_import(module_name: str, function_name: str) -> Any:
    """
    Unsafe dynamic import
    Vulnerability: Importing arbitrary modules
    Severity: High
    """
    # Blocklist attempt (incomplete)
    blocked = ["os", "subprocess", "sys", "ctypes"]
    
    if module_name in blocked:
        raise ValueError("Module not allowed")
    
    # VULN: Can import submodules of blocked modules
    # Attack: module_name = "os.path" (bypasses blocklist)
    
    # Import module
    module = __import__(module_name)  # VULN: Arbitrary import
    
    # Get function
    func = getattr(module, function_name)
    return func


# ============ VULNERABILITY 8: Race condition TOCTOU ============
def vulnerable_file_race(filename: str, data: str) -> bool:
    """
    TOCTOU race condition
    Vulnerability: Check-then-use pattern
    Severity: Medium-High
    """
    # Check if file exists and is writable
    if not os.path.exists(filename):
        return False
    
    # Check permissions
    if not os.access(filename, os.W_OK):
        return False
    
    # Between check and write, attacker can replace file with symlink
    # VULN: Time-of-check to time-of-use race condition
    
    # Write to file
    with open(filename, 'w') as f:  # VULN: Race condition
        f.write(data)
    
    return True


# ============ VULNERABILITY 9: Cryptography misuse - predictable IV ============
class VulnerableEncryption:
    def __init__(self, key: bytes):
        self.key = key
    
    def encrypt(self, plaintext: str) -> bytes:
        """
        Cryptography vulnerability
        Vulnerability: Predictable IV/CBC mode issues
        Severity: High
        """
        import hashlib
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        import os
        
        # Use static IV (BAD!)
        iv = b"1234567890123456"  # VULN: Static IV
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        
        return iv + ciphertext  # IV prepended
    
    def decrypt(self, ciphertext: bytes) -> str:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        
        iv = ciphertext[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
        
        return plaintext.decode()


# ============ VULNERABILITY 10: Memory corruption via ctypes ============
def vulnerable_memory_operation(buffer_data: bytes) -> int:
    """
    Potential memory corruption
    Vulnerability: Unsafe C function calls
    Severity: Critical
    """
    # Load C library
    libc = ctypes.CDLL(None)
    
    # Get memcpy function
    memcpy = libc.memcpy
    
    # Create buffers
    src = ctypes.create_string_buffer(buffer_data)
    dst = ctypes.create_string_buffer(100)  # Fixed size buffer
    
    # VULN: No bounds checking
    # If buffer_data is > 100 bytes, buffer overflow
    memcpy(dst, src, len(buffer_data))  # VULN: Buffer overflow
    
    return len(dst.value)


# ============ VULNERABILITY 11: Log injection with newline characters ============
class VulnerableLogger:
    def __init__(self, log_file: str):
        self.log_file = log_file
    
    def log_event(self, username: str, action: str):
        """
        Log injection vulnerability
        Vulnerability: Unsanitized log entries
        Severity: Medium
        """
        timestamp = datetime.datetime.now().isoformat()
        
        # VULN: User input goes directly into log without sanitization
        log_entry = f"{timestamp} - User: {username} - Action: {action}\n"
        
        # Attack: username = "admin\n[ERROR] Database corrupted"
        # Creates fake error log entry
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry)  # VULN: Log injection


# ============ VULNERABILITY 12: Regex DoS (ReDoS) ============
def vulnerable_regex_match(text: str, pattern: str) -> bool:
    """
    ReDoS vulnerability
    Vulnerability: Exponential backtracking regex
    Severity: Medium-High
    """
    # User-provided regex pattern (DANGEROUS!)
    # VULN: Allowing user-provided regex patterns
    
    # Compile and match
    try:
        regex = re.compile(pattern)  # VULN: User-controlled regex
        return bool(regex.match(text))
    except re.error:
        return False


# ============ VULNERABILITY 13: Insecure randomness ============
def vulnerable_password_reset_token(user_id: int) -> str:
    """
    Cryptographically weak randomness
    Vulnerability: Using random() not secrets
    Severity: Medium
    """
    import random
    import time
    
    # VULN: Using predictable random (time-based seed)
    random.seed(time.time() + user_id)
    
    # Generate "random" token
    token = ''.join(random.choices('abcdef0123456789', k=32))  # VULN: Weak randomness
    
    return token


# ============ VULNERABILITY 14: YAML deserialization attack ============
def vulnerable_yaml_load(yaml_data: str) -> Any:
    """
    YAML deserialization RCE
    Vulnerability: Unsafe YAML loading
    Severity: Critical
    """
    # Using unsafe loader
    # Attack: !!python/object/apply:os.system ["cat /etc/passwd"]
    
    # Try to block dangerous YAML tags (incomplete)
    if "!!python" in yaml_data:
        raise ValueError("Dangerous YAML construct")
    
    # VULN: Still vulnerable to other payloads
    # Can use anchors/references or other dangerous constructs
    
    data = yaml.load(yaml_data, Loader=yaml.Loader)  # VULN: Unsafe YAML loading
    return data


# ============ VULNERABILITY 15: Type confusion/attribute injection ============
class User:
    def __init__(self, username: str):
        self.username = username
        self.is_admin = False
    
    def __str__(self):
        return f"User({self.username}, admin={self.is_admin})"


def vulnerable_object_deserialize(data: Dict) -> User:
    """
    Type confusion/attribute injection
    Vulnerability: Setting arbitrary attributes
    Severity: High
    """
    user = User(data.get('username', 'guest'))
    
    # VULN: Setting arbitrary attributes from untrusted data
    for key, value in data.items():
        if hasattr(user, key):
            setattr(user, key, value)  # VULN: Attribute injection
    
    # Attack: data = {'username': 'admin', 'is_admin': True, '__class__': ...}
    # Can manipulate object internals
    
    return user


# ============ BONUS VULNERABILITY: Prototype pollution ============
def vulnerable_dict_merge(target: Dict, source: Dict) -> Dict:
    """
    Prototype pollution (Python style)
    Vulnerability: Modifying object prototypes
    Severity: High
    """
    # Recursive merge
    for key, value in source.items():
        if isinstance(value, dict) and key in target and isinstance(target[key], dict):
            vulnerable_dict_merge(target[key], value)
        else:
            # VULN: Can overwrite special attributes
            target[key] = value
    
    # Attack: source = {'__proto__': {'polluted': True}}
    # or in Python: {'__class__': {'__init__': malicious_code}}
    
    return target


# ============ MAIN APPLICATION (VULNERABLE WEB SERVER) ============
class VulnerableHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests with multiple vulnerabilities"""
        
        # Parse query parameters
        query = parse_qs(urlparse(self.path).query)
        
        # VULN: Reflected XSS
        name = query.get('name', [''])[0]
        
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # VULN: XSS - user input directly in response
        response = f"""
        <html>
        <body>
            <h1>Welcome, {name}!</h1>  <!-- VULN: Reflected XSS -->
            <p>Your user agent: {self.headers.get('User-Agent')}</p>
        </body>
        </html>
        """
        
        self.wfile.write(response.encode())
    
    def do_POST(self):
        """Handle POST requests with vulnerabilities"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Parse as JSON
        try:
            data = json.loads(post_data)
            
            # Process with various vulnerable functions
            if 'action' in data:
                if data['action'] == 'encrypt':
                    enc = VulnerableEncryption(b'1234567890123456')
                    result = enc.encrypt(data['text'])
                    response = base64.b64encode(result).decode()
                
                elif data['action'] == 'deserialize':
                    result = vulnerable_deserialization(
                        base64.b64decode(data['pickle']),
                        'weak_secret'
                    )
                    response = str(result)
                
                elif data['action'] == 'template':
                    result = vulnerable_template_render(
                        data['template'],
                        data.get('context', {})
                    )
                    response = result
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'result': response}).encode())
                return
        
        except Exception as e:
            pass
        
        self.send_response(400)
        self.end_headers()


def start_vulnerable_server(port: int = 8080):
    """Start the vulnerable HTTP server"""
    server = HTTPServer(('localhost', port), VulnerableHTTPHandler)
    print(f"Starting vulnerable server on port {port}...")
    print("WARNING: This server has intentional vulnerabilities!")
    server.serve_forever()


# ============ DEMONSTRATION FUNCTIONS ============
def demonstrate_vulnerabilities():
    """Demonstrate how to exploit the vulnerabilities"""
    print("=== SECURITY VULNERABILITY DEMONSTRATIONS ===")
    print("For educational purposes only!")
    print()
    
    # Demo 1: Command Injection
    print("1. Command Injection:")
    print("   Input: 'filename; cat /etc/passwd'")
    print("   Bypasses shlex.quote with shell=True")
    print()
    
    # Demo 2: SQL Injection
    db = VulnerableDatabase()
    print("2. SQL Injection:")
    print(f"   Normal query: {db.get_user_secret('1')}")
    print("   Malicious: db.get_user_secret('1 OR 1=1 --')")
    print()
    
    # Demo 3: Pickle RCE
    print("3. Pickle Deserialization RCE:")
    print("   Can execute: __import__('os').system('id')")
    print()
    
    # Demo 4: XXE
    print("4. XXE:")
    print("   Can read files: <!ENTITY xxe SYSTEM 'file:///etc/passwd'>")
    print()
    
    # Demo 5: Path Traversal
    print("5. Path Traversal with Unicode:")
    print("   Use Unicode backslash: ..%u2216..%u2216etc%u2216passwd")
    print()
    
    # Demo 11: Log Injection
    logger = VulnerableLogger('/tmp/vuln.log')
    print("11. Log Injection:")
    print("   Username: admin\\n[ERROR] Database corrupted")
    print("   Creates fake log entries")
    print()
    
    print("=== END DEMONSTRATION ===")
    print()
    print("REMINDER: This code is for educational purposes only!")
    print("Never deploy code with these vulnerabilities in production!")


if __name__ == "__main__":
    # Parse command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demonstrate_vulnerabilities()
    elif len(sys.argv) > 1 and sys.argv[1] == "--server":
        start_vulnerable_server()
    else:
        print("Vulnerability Demonstration Code")
        print("Usage:")
        print("  python vulnerabilities.py --demo    Show vulnerability demonstrations")
        print("  python vulnerabilities.py --server  Start vulnerable HTTP server")
        print()
        print("WARNING: This code contains intentional security vulnerabilities!")
        print("Use only in controlled, isolated environments for education.")