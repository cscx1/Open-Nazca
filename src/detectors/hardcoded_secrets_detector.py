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
            
            # Check each secret pattern
            for pattern, secret_type, severity, description in self.secret_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
                for match in matches:
                    # Extract the secret value (if captured in group)
                    secret_value = match.group(1) if match.groups() else match.group()
                    
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
                    logger.info(
                        f"✓ Detected {secret_type} at {file_name}:{line_num}"
                    )
        
        # Perform fuzzy detection for potential secrets
        findings.extend(self._fuzzy_detect_secrets(code, file_name))
        
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
    
    def _fuzzy_detect_secrets(self, code: str, file_name: str) -> List[Finding]:
        """
        Fuzzy detection for potential secrets based on keywords and patterns.
        
        Args:
            code: Full source code
            file_name: Name of the file
        
        Returns:
            List of additional findings
        """
        findings = []
        lines = code.split('\n')
        
        # Track if we're inside a docstring
        in_docstring = False
        
        for line_num, line in enumerate(lines, 1):
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
                        # Lower confidence fuzzy match
                        snippet = self.extract_code_snippet(code, line_num, context_lines=2)
                        
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
                        logger.info(
                            f"✓ Detected potential secret at {file_name}:{line_num} "
                            f"(keyword: {keyword}, confidence: 60%)"
                        )
                        break  # Only report once per line
        
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

