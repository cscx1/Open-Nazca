"""
Hardcoded Secrets Detector for AI Code Breaker
Detects API keys, tokens, and passwords hardcoded in source code.
"""

import re
from typing import List, Tuple
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


class HardcodedSecretsDetector(BaseDetector):
    """
    Detects hardcoded secrets, API keys, tokens, and passwords in code.
    
    This is CRITICAL because exposed secrets can lead to unauthorized
    access to systems, data breaches, and financial losses.
    """
    
    def __init__(self, enabled: bool = True):
        super().__init__("HardcodedSecretsDetector", enabled)
        
        # Patterns for detecting different types of secrets
        # Format: (pattern, secret_type, severity, description)
        self.secret_patterns: List[Tuple[str, str, str, str]] = [
            # API Keys
            (r'["\']?api[_-]?key["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
             'API Key', 'CRITICAL', 'Hardcoded API key detected'),
            
            (r'["\']?openai[_-]?api[_-]?key["\']?\s*[=:]\s*["\']sk-[A-Za-z0-9]{40,}["\']',
             'OpenAI API Key', 'CRITICAL', 'OpenAI API key exposed'),
            
            (r'["\']?anthropic[_-]?api[_-]?key["\']?\s*[=:]\s*["\']sk-ant-[A-Za-z0-9\-]{40,}["\']',
             'Anthropic API Key', 'CRITICAL', 'Anthropic/Claude API key exposed'),
            
            # Client ID/Secret patterns (common for OAuth APIs like Spotify, Google, etc.)
            (r'CLIENT[_-]?ID\s*=\s*["\']([A-Za-z0-9_\-]{20,})["\']',
             'Client ID', 'CRITICAL', 'Hardcoded client ID detected'),
            
            (r'CLIENT[_-]?SECRET\s*=\s*["\']([A-Za-z0-9_\-]{16,})["\']',
             'Client Secret', 'CRITICAL', 'Hardcoded client secret detected'),
            
            (r'client[_-]?id\s*=\s*["\']([A-Za-z0-9_\-]{20,})["\']',
             'Client ID', 'CRITICAL', 'Hardcoded client ID detected'),
            
            (r'client[_-]?secret\s*=\s*["\']([A-Za-z0-9_\-]{16,})["\']',
             'Client Secret', 'CRITICAL', 'Hardcoded client secret detected'),
            
            # AWS Keys
            (r'AKIA[0-9A-Z]{16}',
             'AWS Access Key', 'CRITICAL', 'AWS access key ID exposed'),
            
            (r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
             'AWS Secret Key', 'CRITICAL', 'AWS secret access key exposed'),
            
            # Generic Secrets
            (r'["\']?secret[_-]?key["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
             'Secret Key', 'CRITICAL', 'Hardcoded secret key detected'),
            
            (r'["\']?auth[_-]?token["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',
             'Auth Token', 'CRITICAL', 'Hardcoded authentication token'),
            
            # Passwords
            (r'["\']?password["\']?\s*[=:]\s*["\']([^"\']{8,})["\']',
             'Password', 'CRITICAL', 'Hardcoded password detected'),
            
            (r'["\']?db[_-]?password["\']?\s*[=:]\s*["\']([^"\']{4,})["\']',
             'Database Password', 'CRITICAL', 'Hardcoded database password'),
            
            # GitHub & Git
            (r'gh[pousr]_[A-Za-z0-9_]{36,}',
             'GitHub Token', 'CRITICAL', 'GitHub personal access token exposed'),
            
            # Slack
            (r'xox[baprs]-[0-9a-zA-Z\-]{10,}',
             'Slack Token', 'CRITICAL', 'Slack API token exposed'),
            
            # JWT Tokens (very long base64 strings with dots)
            (r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
             'JWT Token', 'HIGH', 'Potential JWT token hardcoded'),
            
            # Private Keys
            (r'-----BEGIN (?:RSA |)PRIVATE KEY-----',
             'Private Key', 'CRITICAL', 'Private key embedded in code'),
            
            # Connection Strings
            (r'(?:mongodb|mysql|postgresql)://[^:]+:[^@]+@',
             'Database Connection String', 'CRITICAL', 'Database credentials in connection string'),
        ]
        
        # Keywords that indicate secrets (for fuzzy detection)
        self.secret_keywords = [
            'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
            'token', 'auth', 'credential', 'private_key', 'access_key'
        ]
        
        # Patterns to exclude (common false positives)
        self.exclude_patterns = [
            r'password["\']?\s*[=:]\s*["\'](?:your_password|example|test|password|12345|change_me)',
            r'api[_-]?key["\']?\s*[=:]\s*["\'](?:your_api_key|YOUR_API_KEY|example)',
            r'\.env|getenv|os\.environ',  # Environment variables (safe)
        ]
    
    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        """
        Detect hardcoded secrets in code.
        
        Args:
            code: Source code to analyze
            language: Programming language
            file_name: Name of the file
        
        Returns:
            List of Finding objects
        """
        findings = []
        lines = code.split('\n')
        
        # Track lines that already have pattern matches (to avoid duplicate fuzzy detection)
        lines_with_pattern_match = set()
        
        # Track if we're inside a docstring
        in_docstring = False
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Track docstring boundaries (triple quotes)
            docstring_count = line.count('"""') + line.count("'''")
            if docstring_count == 1:
                in_docstring = not in_docstring
            elif docstring_count >= 2:
                # Opening and closing on same line - skip this line
                continue
            
            # Skip empty lines, comments, and docstrings
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue
            if in_docstring:
                continue
            
            # Check if line is excluded (environment variable usage, etc.)
            if self._is_excluded(line):
                continue
            
            # Check each secret pattern (only one match per line to avoid duplicates)
            line_already_matched = False
            for pattern, secret_type, severity, description in self.secret_patterns:
                if line_already_matched:
                    break
                    
                matches = list(re.finditer(pattern, line, re.IGNORECASE))
                
                if matches:
                    match = matches[0]  # Only use first match
                    # Extract the secret value (if captured in group)
                    secret_value = match.group(1) if match.groups() else match.group()
                    
                    # Skip false positives: template / f-string variable
                    # references like {password}, {username}, {api_key}.
                    # These are interpolation placeholders, not real secrets.
                    if re.fullmatch(r'\{[\w.]+\}', secret_value.strip()):
                        continue
                    
                    # Mask the secret for display (show first/last 4 chars)
                    masked_secret = self._mask_secret(secret_value)
                    
                    # Extract code snippet (without the full secret)
                    snippet = self.extract_code_snippet(code, line_num, context_lines=2)
                    masked_snippet = self._mask_secret_in_snippet(snippet, secret_value)
                    
                    # Create finding
                    finding = Finding(
                        detector_name=self.name,
                        vulnerability_type="Hardcoded Secret",
                        severity=severity,
                        line_number=line_num,
                        code_snippet=masked_snippet,
                        description=(
                            f"{description}: {secret_type} appears to be hardcoded. "
                            f"Hardcoded secrets can be extracted by attackers who gain "
                            f"access to source code, version control history, or compiled "
                            f"binaries. This can lead to unauthorized access, data breaches, "
                            f"and service compromise. Value: {masked_secret}"
                        ),
                        confidence=0.90,
                        cwe_id="CWE-798",  # Use of Hard-coded Credentials
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                        metadata={
                            'secret_type': secret_type,
                            'masked_value': masked_secret,
                            'pattern_matched': pattern
                        }
                    )
                    
                    findings.append(finding)
                    lines_with_pattern_match.add(line_num)  # Track this line
                    line_already_matched = True  # Don't match more patterns on this line
                    logger.info(
                        f"✓ Detected {secret_type} at {file_name}:{line_num}"
                    )
        
        # Perform fuzzy detection for potential secrets (skip lines already matched)
        findings.extend(self._fuzzy_detect_secrets(code, file_name, lines_with_pattern_match))
        
        # Detect secrets exposed in print/log statements
        findings.extend(self._detect_printed_secrets(code, file_name))
        
        # Detect dangerous secret aggregation functions
        findings.extend(self._detect_secret_aggregation(code, file_name))
        
        self.findings = findings
        return findings
    
    def _is_excluded(self, line: str) -> bool:
        """
        Check if line matches exclusion patterns (e.g., uses environment variables).
        
        Args:
            line: Line of code to check
        
        Returns:
            True if line should be excluded from detection
        """
        for pattern in self.exclude_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False
    
    def _mask_secret(self, secret: str, show_chars: int = 4) -> str:
        """
        Mask a secret value for safe display.
        
        Args:
            secret: Secret value to mask
            show_chars: Number of characters to show at start/end
        
        Returns:
            Masked secret (e.g., "sk-a...xyz")
        """
        if len(secret) <= show_chars * 2:
            return "*" * len(secret)
        
        return f"{secret[:show_chars]}...{secret[-show_chars:]}"
    
    def _mask_secret_in_snippet(self, snippet: str, secret: str) -> str:
        """
        Replace secret with masked version in code snippet.
        
        Args:
            snippet: Code snippet
            secret: Secret to mask
        
        Returns:
            Snippet with masked secret
        """
        masked = self._mask_secret(secret)
        return snippet.replace(secret, masked)
    
    def _fuzzy_detect_secrets(self, code: str, file_name: str, skip_lines: set = None) -> List[Finding]:
        """
        Fuzzy detection for potential secrets based on keywords and patterns.
        
        Args:
            code: Full source code
            file_name: Name of the file
            skip_lines: Set of line numbers to skip (already matched by patterns)
        
        Returns:
            List of additional findings
        """
        findings = []
        lines = code.split('\n')
        skip_lines = skip_lines or set()
        
        # Track if we're inside a docstring
        in_docstring = False
        
        for line_num, line in enumerate(lines, 1):
            # Skip lines that already have pattern matches
            if line_num in skip_lines:
                continue
                
            stripped = line.strip()
            
            # Track docstring boundaries (triple quotes)
            docstring_count = line.count('"""') + line.count("'''")
            if docstring_count == 1:
                in_docstring = not in_docstring
            elif docstring_count >= 2:
                # Opening and closing on same line - skip this line but don't toggle
                continue
            
            # Skip comments, docstrings, and excluded lines
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            if in_docstring:
                continue
            if self._is_excluded(line):
                continue
            
            # Look for secret keywords combined with string assignments
            for keyword in self.secret_keywords:
                if keyword in line.lower():
                    # Check if there's a string value assigned (basic heuristic)
                    # Must have actual assignment, not just keyword in string
                    if re.search(r'^\s*\w+\s*[=:]\s*["\'][^"\']{10,}["\']', line):
                        snippet = self.extract_code_snippet(code, line_num, context_lines=2)
                        
                        # Check if the value is a URL - lower severity/confidence
                        is_url = bool(re.search(r'https?://', line))
                        
                        if is_url:
                            # URLs with secret keywords are low-priority potential threats
                            finding = Finding(
                                detector_name=self.name,
                                vulnerability_type="Potential Threat - URL with Secret Keyword",
                                severity="LOW",
                                line_number=line_num,
                                code_snippet=snippet,
                                description=(
                                    f"URL contains secret-related keyword '{keyword}'. "
                                    f"This is likely a public API endpoint, but review to ensure "
                                    f"no sensitive parameters or credentials are embedded in the URL."
                                ),
                                confidence=0.30,
                                cwe_id="CWE-598",  # Use of GET Request Method With Sensitive Query Strings
                                owasp_category="A07:2021 – Identification and Authentication Failures",
                                metadata={
                                    'detection_type': 'url_with_keyword',
                                    'keyword': keyword,
                                    'is_url': True
                                }
                            )
                        else:
                            # Regular fuzzy match - medium severity
                            finding = Finding(
                                detector_name=self.name,
                                vulnerability_type="Potential Hardcoded Secret",
                                severity="MEDIUM",
                                line_number=line_num,
                                code_snippet=snippet,
                                description=(
                                    f"Potential secret detected: variable name contains '{keyword}' "
                                    f"and appears to have a hardcoded value. Manual review recommended. "
                                    f"If this is a secret, it should be stored in environment variables "
                                    f"or a secure secret management system."
                                ),
                                confidence=0.60,
                                cwe_id="CWE-798",
                                owasp_category="A07:2021 – Identification and Authentication Failures",
                                metadata={
                                    'detection_type': 'fuzzy',
                                    'keyword': keyword
                                }
                            )
                        
                        findings.append(finding)
                        severity_label = "LOW (URL)" if is_url else "MEDIUM"
                        logger.info(
                            f"✓ Detected potential {'threat' if is_url else 'secret'} at {file_name}:{line_num} "
                            f"(keyword: {keyword}, severity: {severity_label})"
                        )
                        break  # Only report once per line
        
        return findings
    
    def _detect_printed_secrets(self, code: str, file_name: str) -> List[Finding]:
        """
        Detect secrets being printed or logged to console.
        
        Args:
            code: Full source code
            file_name: Name of the file
        
        Returns:
            List of findings for printed secrets
        """
        findings = []
        lines = code.split('\n')
        
        # Secret variable patterns to look for in print/log statements
        secret_var_patterns = [
            r'api[_-]?key', r'secret', r'password', r'token', r'credential',
            r'client[_-]?id', r'client[_-]?secret', r'access[_-]?key', r'auth'
        ]
        
        # Print/log function patterns
        log_patterns = [
            r'print\s*\(.*?["\'].*?\{(\w+)\}',  # f-string in print
            r'print\s*\(.*?\+\s*(\w+)',  # concatenation in print
            r'print\s*\(.+%.*?\((\w+)\)',  # % formatting
            r'print\s*\(.*?\.format\(.*?(\w+)',  # .format()
            r'logger?\.\w+\s*\(.*?\{(\w+)\}',  # logging with f-string
            r'logging\.\w+\s*\(.*?\{(\w+)\}',  # logging module
        ]
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            
            # Check if line contains print/log with potential secret variable
            for log_pattern in log_patterns:
                match = re.search(log_pattern, line, re.IGNORECASE)
                if match:
                    var_name = match.group(1).lower() if match.groups() else ''
                    
                    # Check if the variable name looks like a secret
                    for secret_pattern in secret_var_patterns:
                        if re.search(secret_pattern, var_name, re.IGNORECASE) or \
                           re.search(secret_pattern, line, re.IGNORECASE):
                            snippet = self.extract_code_snippet(code, line_num, context_lines=2)
                            
                            finding = Finding(
                                detector_name=self.name,
                                vulnerability_type="Secret Exposed in Logs",
                                severity="HIGH",
                                line_number=line_num,
                                code_snippet=snippet,
                                description=(
                                    f"Secret or sensitive value appears to be printed/logged. "
                                    f"This exposes credentials in console output, log files, and "
                                    f"potentially monitoring systems. Attackers with access to logs "
                                    f"can extract these secrets. Never print API keys, passwords, "
                                    f"or tokens to output."
                                ),
                                confidence=0.85,
                                cwe_id="CWE-532",  # Insertion of Sensitive Information into Log File
                                owasp_category="A09:2021 – Security Logging and Monitoring Failures",
                                metadata={
                                    'detection_type': 'printed_secret',
                                    'variable': var_name
                                }
                            )
                            
                            findings.append(finding)
                            logger.info(
                                f"✓ Detected printed secret at {file_name}:{line_num}"
                            )
                            break
                    break
        
        return findings
    
    def _detect_secret_aggregation(self, code: str, file_name: str) -> List[Finding]:
        """
        Detect functions that aggregate multiple secrets (potential data exfiltration).
        
        Args:
            code: Full source code
            file_name: Name of the file
        
        Returns:
            List of findings for secret aggregation
        """
        findings = []
        lines = code.split('\n')
        
        # Look for functions that collect sensitive values
        # Pattern: function that takes multiple secret-like parameters or collects them
        sensitive_keywords = ['secret', 'password', 'token', 'key', 'credential', 'auth']
        
        in_function = False
        function_start = 0
        function_name = ''
        secret_params_count = 0
        secret_operations = 0
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Detect function definition with sensitive parameters
            func_match = re.match(r'def\s+(\w+)\s*\(([^)]*)\)', line)
            if func_match:
                function_name = func_match.group(1)
                params = func_match.group(2).lower()
                
                # Count sensitive parameters — each keyword must match a
                # DISTINCT parameter name, not just appear as a substring
                # of the full params string.
                param_names = [p.strip().split(':')[0].split('=')[0].strip()
                               for p in params.split(',')]
                secret_params_count = 0
                matched_params: set = set()
                for pname in param_names:
                    for kw in sensitive_keywords:
                        if kw in pname and pname not in matched_params:
                            secret_params_count += 1
                            matched_params.add(pname)
                            break

                if secret_params_count >= 3 or 'sensitive' in function_name.lower() or \
                   'collect' in function_name.lower() or 'stash' in function_name.lower():
                    in_function = True
                    function_start = line_num
                    secret_operations = 0
            
            # Track operations inside suspicious functions
            if in_function:
                # Look for aggregation patterns (append, join, concatenate)
                if re.search(r'\.append\(|\.extend\(|\.join\(|\+\s*=|\+=', line):
                    secret_operations += 1
                
                # End of function (next def or significant dedent)
                if line_num > function_start and (line.startswith('def ') or 
                    (stripped and not line.startswith(' ') and not line.startswith('\t'))):
                    
                    if secret_operations >= 3 or secret_params_count >= 3:
                        snippet = self.extract_code_snippet(code, function_start, context_lines=5)
                        
                        finding = Finding(
                            detector_name=self.name,
                            vulnerability_type="Dangerous Secret Aggregation",
                            severity="HIGH",
                            line_number=function_start,
                            code_snippet=snippet,
                            description=(
                                f"Function '{function_name}' appears to aggregate multiple secrets "
                                f"or sensitive values. This pattern is commonly used for data "
                                f"exfiltration - collecting credentials into a single payload for "
                                f"theft. Functions should not combine multiple secrets. Each secret "
                                f"should be handled separately with minimal exposure."
                            ),
                            confidence=0.80,
                            cwe_id="CWE-200",  # Exposure of Sensitive Information
                            owasp_category="A01:2021 – Broken Access Control",
                            metadata={
                                'detection_type': 'secret_aggregation',
                                'function_name': function_name,
                                'secret_params': secret_params_count,
                                'aggregation_operations': secret_operations
                            }
                        )
                        
                        findings.append(finding)
                        logger.info(
                            f"✓ Detected secret aggregation at {file_name}:{function_start} "
                            f"(function: {function_name})"
                        )
                    
                    in_function = False
        
        return findings


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    detector = HardcodedSecretsDetector()
    
    # Example vulnerable code
    test_code = '''
# VULNERABLE: Hardcoded API key
openai_api_key = "sk-proj1234567890abcdefghijklmnopqrstuvwxyz"

# VULNERABLE: AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# SAFE: Using environment variable
api_key = os.getenv("OPENAI_API_KEY")
    '''
    
    findings = detector.detect(test_code, 'python', 'test.py')
    print(f"Found {len(findings)} hardcoded secrets")

