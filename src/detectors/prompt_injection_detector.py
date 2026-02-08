"""
Prompt Injection Detector for AI Code Breaker
Detects unsafe concatenation of user input into AI prompts.
"""

import re
from typing import List
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


class PromptInjectionDetector(BaseDetector):
    """
    Detects prompt injection vulnerabilities where user input is
    concatenated directly into LLM prompts without sanitization.
    
    This is CRITICAL because attackers can manipulate AI behavior by
    injecting malicious instructions into prompts.
    """
    
    def __init__(self, enabled: bool = True):
        super().__init__("PromptInjectionDetector", enabled)
        
        # Dangerous patterns that indicate prompt injection risk
        self.dangerous_patterns = [
            # Python f-string patterns
            (r'f["\'].*?\{user[_\w]*\}', 'F-string with user input'),
            (r'f["\'].*?\{.*?input\(\)', 'F-string with input() call'),
            
            # String concatenation patterns
            (r'\+\s*user[_\w]*', 'String concatenation with user variable'),
            (r'user[_\w]*\s*\+', 'String concatenation with user variable'),
            (r'\.format\(.*?user', 'format() with user input'),
            
            # Template string patterns (JavaScript/TypeScript)
            (r'`.*?\$\{user[_\w]*\}', 'Template literal with user input'),
            (r'`.*?\$\{.*?prompt\(', 'Template literal with prompt()'),
            
            # Direct variable insertion
            (r'prompt\s*=\s*["\'].*?["\'].*?\+.*?user', 'Prompt concatenation with user input'),
            (r'system_prompt.*?\+.*?user', 'System prompt concatenation'),
        ]
        
        # Keywords that suggest AI/LLM usage
        self.ai_keywords = [
            'prompt', 'system_prompt', 'user_prompt', 'instruction',
            'gpt', 'openai', 'anthropic', 'claude', 'llm', 'ai_model',
            'completion', 'chat', 'message'
        ]
    
    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        """
        Detect prompt injection vulnerabilities in code.
        
        Args:
            code: Source code to analyze
            language: Programming language
            file_name: Name of the file
        
        Returns:
            List of Finding objects
        """
        findings = []
        
        if language not in ['python', 'javascript', 'typescript']:
            logger.debug(f"Skipping prompt injection check for {language}")
            return findings
        
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue
            
            # Check if line contains AI-related keywords
            has_ai_context = any(keyword in line.lower() for keyword in self.ai_keywords)
            
            # Check each dangerous pattern
            for pattern, description in self.dangerous_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
                for match in matches:
                    # RULE: Only classify as Prompt Injection if the line
                    # has AI/LLM context.  Without LLM context the matched
                    # pattern (e.g. f-string with {username}) is likely
                    # SQL concatenation, template rendering, or another
                    # injection class — NOT prompt injection.  The AST
                    # pipeline will classify those by sink.
                    if not has_ai_context:
                        logger.debug(
                            f"Suppressed prompt-injection pattern at "
                            f"{file_name}:{line_num} — no AI/LLM context"
                        )
                        continue
                    
                    # Extract code snippet
                    snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                    
                    confidence = 0.95
                    
                    # Create finding
                    finding = Finding(
                        detector_name=self.name,
                        vulnerability_type="Prompt Injection",
                        severity="CRITICAL",
                        line_number=line_num,
                        code_snippet=snippet,
                        description=(
                            f"User input is concatenated directly into a string that is "
                            f"used as an AI/LLM prompt. {description}. This allows attackers to "
                            f"inject malicious instructions that can manipulate AI behavior, "
                            f"bypass security controls, or extract sensitive information."
                        ),
                        confidence=confidence,
                        cwe_id="CWE-74",  # Improper Neutralization of Special Elements
                        owasp_category="A03:2021 – Injection",
                        metadata={
                            'pattern': pattern,
                            'matched_text': match.group(),
                            'has_ai_context': has_ai_context
                        }
                    )
                    
                    findings.append(finding)
                    logger.info(
                        f"✓ Detected prompt injection at {file_name}:{line_num} "
                        f"(confidence: {confidence:.0%})"
                    )
        
        # Check for specific high-risk patterns across multiple lines
        findings.extend(self._detect_multiline_patterns(code, file_name))
        
        self.findings = findings
        return findings
    
    def _detect_multiline_patterns(self, code: str, file_name: str) -> List[Finding]:
        """
        Detect prompt injection patterns that span multiple lines.
        
        Args:
            code: Full source code
            file_name: Name of the file
        
        Returns:
            List of additional findings
        """
        findings = []
        
        # Pattern: Variable assigned user input, then used in prompt
        # Example:
        #   user_query = input()
        #   prompt = f"System: You are helpful. User: {user_query}"
        
        lines = code.split('\n')
        user_vars = {}  # var_name -> line_number where defined
        
        for line_num, line in enumerate(lines, 1):
            # Find variables that receive user input
            user_input_pattern = r'(\w+)\s*=\s*(?:input\(|request\.form|request\.json|params\[)'
            match = re.search(user_input_pattern, line)
            if match:
                var_name = match.group(1)
                user_vars[var_name] = line_num  # Remember where it was defined
            
            # Check if user variables are used in potential prompts (on a DIFFERENT line)
            if user_vars:
                for var, def_line in user_vars.items():
                    # Skip if this is the line where the variable is defined
                    if line_num == def_line:
                        continue
                    
                    # Check if this line uses the user variable in a prompt-like context
                    # Use word boundary check to avoid matching substrings in variable names
                    if re.search(rf'\b{re.escape(var)}\b', line):
                        # Check for actual AI keywords (not just in variable names)
                        ai_context = any(
                            re.search(rf'\b{re.escape(kw)}\b', line.lower()) 
                            for kw in ['prompt', 'system_prompt', 'gpt', 'openai', 
                                       'anthropic', 'claude', 'llm', 'completion', 'chat']
                        )
                        
                        if ai_context:
                            snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                            
                            finding = Finding(
                                detector_name=self.name,
                                vulnerability_type="Prompt Injection",
                                severity="CRITICAL",
                                line_number=line_num,
                                code_snippet=snippet,
                                description=(
                                    f"User-controlled variable '{var}' is used in AI prompt context. "
                                    f"This can allow prompt injection attacks where malicious users "
                                    f"inject instructions to manipulate AI behavior."
                                ),
                                confidence=0.85,
                                cwe_id="CWE-74",
                                owasp_category="A03:2021 – Injection",
                                metadata={
                                    'user_variable': var,
                                    'detection_type': 'multiline_analysis'
                                }
                            )
                            
                            findings.append(finding)
                            break  # Only report once per line
        
        return findings


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    detector = PromptInjectionDetector()
    
    # Example vulnerable code
    test_code = '''
def chat_with_ai(user_input):
    # VULNERABLE: Direct concatenation
    prompt = f"You are a helpful assistant. User says: {user_input}"
    response = openai.Completion.create(prompt=prompt)
    return response
    '''
    
    findings = detector.detect(test_code, 'python', 'test.py')
    print(f"Found {len(findings)} prompt injection vulnerabilities")

