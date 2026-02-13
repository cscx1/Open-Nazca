"""
EXTREMELY VULNERABLE TEST FILE
Contains 20+ intentional security vulnerabilities
FOR EDUCATIONAL/TESTING PURPOSES ONLY
"""

import os
import sys
import pickle
import subprocess
import sqlite3
import json
import yaml
import re
import hashlib
import base64
import xml.etree.ElementTree as ET
from flask import Flask, request, render_template_string
import tempfile
import shlex
import marshal
import random
import datetime

app = Flask(__name__)

# ============ VULNERABILITY 1: Hardcoded credentials ============
DB_PASSWORD = "super_secret_123"
API_KEY = "sk_live_51abc123def456"

# ============ VULNERABILITY 2: Command injection with eval ============
@app.route('/execute', methods=['POST'])
def execute_command():
    """Direct command execution via eval"""
    cmd = request.form.get('command', '')
    # CRITICAL: Direct eval of user input
    result = eval(f"os.system('{cmd}')")
    return f"Result: {result}"

# ============ VULNERABILITY 3: SQL injection ============
def get_user_data(user_id):
    """Direct SQL injection vulnerability"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # CRITICAL: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()

# ============ VULNERABILITY 4: Path traversal ============
@app.route('/readfile')
def read_file():
    """Path traversal vulnerability"""
    filename = request.args.get('file', 'default.txt')
    
    # CRITICAL: No path validation
    with open(filename, 'r') as f:
        return f.read()

# ============ VULNERABILITY 5: XSS via render_template_string ============
@app.route('/greet')
def greet_user():
    """Reflected XSS vulnerability"""
    name = request.args.get('name', 'Guest')
    
    # CRITICAL: Direct user input in template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# ============ VULNERABILITY 6: Unsafe pickle deserialization ============
def load_user_data(data):
    """Pickle deserialization RCE"""
    # CRITICAL: Untrusted pickle loading
    return pickle.loads(base64.b64decode(data))

# ============ VULNERABILITY 7: Weak password hashing ============
def hash_password(password):
    """Weak MD5 password hashing"""
    # VULNERABLE: MD5 is broken
    return hashlib.md5(password.encode()).hexdigest()

# ============ VULNERABILITY 8: Insecure random token ============
def generate_token():
    """Predictable random token"""
    # VULNERABLE: time-based seed
    random.seed(datetime.datetime.now().timestamp())
    return ''.join(random.choices('0123456789', k=6))

# ============ VULNERABILITY 9: XML External Entity ============
def parse_xml(xml_data):
    """XXE vulnerability"""
    # CRITICAL: No XXE protection
    root = ET.fromstring(xml_data)
    return root.tag

# ============ VULNERABILITY 10: Shell injection with shell=True ============
def list_directory(path):
    """Shell injection vulnerability"""
    # CRITICAL: shell=True with user input
    cmd = f"ls -la {path}"
    result = subprocess.check_output(cmd, shell=True)
    return result.decode()

# ============ VULNERABILITY 11: YAML deserialization ============
def load_config(yaml_str):
    """YAML deserialization RCE"""
    # CRITICAL: Unsafe YAML loading
    return yaml.load(yaml_str, Loader=yaml.Loader)

# ============ VULNERABILITY 12: ReDoS vulnerability ============
def validate_email(email):
    """Exponential ReDoS regex"""
    # CRITICAL: Exponential backtracking
    pattern = r'^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+$'
    return bool(re.match(pattern, email))

# ============ VULNERABILITY 13: Mass assignment ============
class User:
    def __init__(self, data):
        # CRITICAL: Mass assignment
        for key, value in data.items():
            setattr(self, key, value)

# ============ VULNERABILITY 14: Log injection ============
def log_action(username, action):
    """Log injection vulnerability"""
    log_msg = f"{datetime.datetime.now()} - {username} - {action}\n"
    with open('app.log', 'a') as f:
        f.write(log_msg)  # CRITICAL: No sanitization

# ============ VULNERABILITY 15: Code injection via exec ============
def dynamic_code_exec(code_str):
    """Direct code execution"""
    # CRITICAL: exec with user input
    exec(code_str)
    return "Code executed"

# ============ VULNERABILITY 16: Unsafe file upload ============
@app.route('/upload', methods=['POST'])
def upload_file():
    """Unsafe file upload"""
    file = request.files['file']
    filename = file.filename
    
    # CRITICAL: No validation, direct save
    file.save(f"/uploads/{filename}")
    return "File uploaded"

# ============ VULNERABILITY 17: Information disclosure ============
@app.route('/debug')
def debug_info():
    """Information disclosure"""
    # CRITICAL: Debug info exposed
    return {
        'python_version': sys.version,
        'cwd': os.getcwd(),
        'env_vars': dict(os.environ)
    }

# ============ VULNERABILITY 18: Insecure direct object reference ============
@app.route('/profile/<user_id>')
def user_profile(user_id):
    """Insecure direct object reference"""
    # CRITICAL: No authorization check
    return f"Profile page for user {user_id}"

# ============ VULNERABILITY 19: Cryptographic weakness ============
def encrypt_data(data, key):
    """Weak encryption with static IV"""
    # CRITICAL: Static IV
    iv = b'0123456789abcdef'
    # Simplified "encryption" for demo
    return base64.b64encode(iv + data.encode())

# ============ VULNERABILITY 20: Race condition ============
def write_to_file(filename, content):
    """TOCTOU race condition"""
    if os.path.exists(filename):
        # CRITICAL: Race between check and write
        with open(filename, 'w') as f:
            f.write(content)
        return True
    return False

# ============ VULNERABILITY 21: Unsafe redirect ============
@app.route('/redirect')
def unsafe_redirect():
    """Open redirect vulnerability"""
    url = request.args.get('url', '/')
    # CRITICAL: No validation of redirect URL
    return f'<meta http-equiv="refresh" content="0; url={url}">'

# ============ VULNERABILITY 22: Server-Side Request Forgery ============
import requests

@app.route('/fetch')
def fetch_url():
    """SSRF vulnerability"""
    url = request.args.get('url')
    # CRITICAL: No URL validation
    response = requests.get(url)
    return response.text

# ============ VULNERABILITY 23: Memory exhaustion ============
def process_large_data(data_size):
    """Memory exhaustion DoS"""
    # CRITICAL: No size limits
    data = 'A' * int(data_size)
    return len(data)

# ============ VULNERABILITY 24: Format string vulnerability ============
def log_with_format(username, action):
    """Format string vulnerability"""
    # CRITICAL: User input in format string
    return f"User {username} performed: {action}".format(username=username, action=action)

# ============ BONUS: Multiple in one function ============
@app.route('/super_vulnerable', methods=['POST'])
def super_vulnerable():
    """Multiple vulnerabilities in one function"""
    data = request.get_json()
    
    # 1. Command injection
    cmd = data.get('cmd', '')
    os.system(cmd)
    
    # 2. SQL injection  
    user_id = data.get('user_id', '1')
    conn = sqlite3.connect('test.db')
    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    
    # 3. Deserialization
    pickle_data = data.get('pickle', '')
    pickle.loads(base64.b64decode(pickle_data))
    
    # 4. XSS
    name = data.get('name', '')
    return f"<script>alert('Hello {name}')</script>"

if __name__ == '__main__':
    app.run(debug=True)  # CRITICAL: Debug mode in production