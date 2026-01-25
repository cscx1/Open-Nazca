"""
Over-Privileged Tools Detector for AI Code Breaker
Detects when LLMs/AI agents are given dangerous permissions or tool access.
"""

import re
from typing import List, Set
from .base_detector import BaseDetector, Finding
import logging

logger = logging.getLogger(__name__)


class OverprivilegedToolsDetector(BaseDetector):
    """
    Detects when LLMs or AI agents are configured with dangerous tools
    or permissions that could be abused.
    
    This is HIGH severity because compromised AI agents with excessive
    permissions can delete data, execute arbitrary code, or cause system damage.
    """
    
    def __init__(self, enabled: bool = True):
        super().__init__("OverprivilegedToolsDetector", enabled)
        
        # Dangerous operations that AI agents should rarely have
        # NOTE: Be specific to avoid false positives (e.g., don't match .format() string method)
        self.dangerous_operations = {
            # File system operations
            'delete_file': 'File deletion',
            'remove_file': 'File removal',
            'os.remove': 'File removal',
            'os.unlink': 'File unlinking/deletion',
            'os.rmdir': 'Directory removal',
            'shutil.rmtree': 'Recursive directory deletion',
            'rm -rf': 'Recursive force deletion',
            
            # Database operations
            'drop table': 'Database DROP TABLE operation',
            'drop database': 'Database DROP operation',
            'truncate table': 'Table truncation',
            'delete from': 'SQL DELETE operation',
            
            # Code execution
            'exec(': 'Arbitrary code execution',
            'eval(': 'Dynamic code evaluation',
            'os.system': 'System command execution',
            'subprocess.run': 'Subprocess execution',
            'subprocess.call': 'Subprocess execution',
            'subprocess.Popen': 'Subprocess spawning',
            'shell=True': 'Shell command execution',
            
            # Network/security
            'sudo': 'Elevated privileges',
            'os.chmod': 'Permission modification',
            'os.chown': 'Ownership modification',
            
            # Destructive operations
            'format_disk': 'Storage formatting',
            'mkfs': 'Filesystem creation',
            'destroy': 'Resource destruction',
            'terminate': 'Process/resource termination',
            'kill': 'Process killing',
        }
        
        # Keywords indicating AI agent/tool usage
        self.agent_keywords = [
            'agent', 'tool', 'function_call', 'tool_call',
            'langchain', 'llm_tool', 'ai_tool', 'agent_executor',
            'tools=', 'available_functions', 'function_calling'
        ]
        
        # Patterns for tool/function definitions
        self.tool_definition_patterns = [
            r'@tool',  # Decorator pattern
            r'Tool\(',  # Tool class instantiation
            r'def\s+\w+_tool\(',  # Function with 'tool' suffix
            r'tools\s*=\s*\[',  # Tools list
            r'function_calling',  # OpenAI function calling
        ]
    
    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        """
        Detect over-privileged AI agent tools.
        
        Args:
            code: Source code to analyze
            language: Programming language
            file_name: Name of the file
        
        Returns:
            List of Finding objects
        """
        findings = []
        
        if language not in ['python', 'javascript', 'typescript']:
            logger.debug(f"Skipping overprivileged tools check for {language}")
            return findings
        
        lines = code.split('\n')
        
        # Track if we're in an agent/tool context
        in_agent_context = False
        context_start_line = 0
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Check if we're entering agent/tool context
            if any(keyword in line.lower() for keyword in self.agent_keywords):
                in_agent_context = True
                context_start_line = line_num
            
            # Reset context after significant whitespace (heuristic)
            if in_agent_context and line_num > context_start_line + 50:
                in_agent_context = False
            
            # Check for dangerous operations
            for operation, description in self.dangerous_operations.items():
                if operation.lower() in line.lower():
                    # Check if this is in a tool/agent context
                    is_tool_definition = any(
                        re.search(pattern, line, re.IGNORECASE)
                        for pattern in self.tool_definition_patterns
                    )
                    
                    # Higher severity if explicitly in agent context
                    severity = "HIGH" if (in_agent_context or is_tool_definition) else "MEDIUM"
                    confidence = 0.90 if (in_agent_context or is_tool_definition) else 0.70
                    
                    # Extract snippet
                    snippet = self.extract_code_snippet(code, line_num, context_lines=3)
                    
                    # Determine specific risk
                    risk_description = self._get_risk_description(operation, description)
                    
                    finding = Finding(
                        detector_name=self.name,
                        vulnerability_type="Over-Privileged AI Tool",
                        severity=severity,
                        line_number=line_num,
                        code_snippet=snippet,
                        description=(
                            f"AI agent or LLM tool appears to have access to dangerous "
                            f"operation: {description} ('{operation}'). {risk_description} "
                            f"AI agents should follow the principle of least privilege and "
                            f"only have access to safe, read-only operations unless absolutely "
                            f"necessary and with proper safeguards."
                        ),
                        confidence=confidence,
                        cwe_id="CWE-269",  # Improper Privilege Management
                        owasp_category="A01:2021 – Broken Access Control",
                        metadata={
                            'operation': operation,
                            'operation_type': description,
                            'in_agent_context': in_agent_context,
                            'is_tool_definition': is_tool_definition
                        }
                    )
                    
                    findings.append(finding)
                    logger.info(
                        f"✓ Detected overprivileged tool at {file_name}:{line_num} "
                        f"(operation: {operation}, severity: {severity})"
                    )
        
        # Perform structural analysis for tool definitions
        findings.extend(self._analyze_tool_structures(code, file_name))
        
        # Detect dangerous permission configs (dicts with shell, delete, etc.)
        findings.extend(self._analyze_permission_configs(code, file_name))
        
        self.findings = findings
        return findings
    
    def _get_risk_description(self, operation: str, description: str) -> str:
        """
        Get specific risk description for an operation.
        
        Args:
            operation: The dangerous operation
            description: General description
        
        Returns:
            Detailed risk description
        """
        risk_descriptions = {
            'delete': 'An attacker could manipulate the AI to delete critical files or data.',
            'drop': 'An attacker could cause data loss by tricking the AI into dropping tables.',
            'exec': 'An attacker could achieve arbitrary code execution through prompt injection.',
            'eval': 'Dynamic code evaluation can be exploited for code injection attacks.',
            'sudo': 'Elevated privileges could lead to system compromise if AI is manipulated.',
            'rm -rf': 'Recursive deletion could cause catastrophic data loss if misused.',
        }
        
        return risk_descriptions.get(
            operation,
            'This operation could be abused if an attacker manipulates the AI through prompt injection.'
        )
    
    def _analyze_tool_structures(self, code: str, file_name: str) -> List[Finding]:
        """
        Analyze structured tool/function definitions for entire AI agents.
        
        Args:
            code: Full source code
            file_name: Name of the file
        
        Returns:
            List of additional findings
        """
        findings = []
        
        # Pattern: tools = [ ... list of tools ... ]
        tools_list_pattern = r'tools\s*=\s*\[(.*?)\]'
        matches = re.finditer(tools_list_pattern, code, re.DOTALL | re.IGNORECASE)
        
        for match in matches:
            tools_content = match.group(1)
            
            # Count dangerous operations in this tools list
            dangerous_ops_found: Set[str] = set()
            for operation in self.dangerous_operations.keys():
                if operation.lower() in tools_content.lower():
                    dangerous_ops_found.add(operation)
            
            if dangerous_ops_found:
                # Find line number of tools definition
                line_num = code[:match.start()].count('\n') + 1
                snippet = self.extract_code_snippet(code, line_num, context_lines=5)
                
                finding = Finding(
                    detector_name=self.name,
                    vulnerability_type="Over-Privileged AI Agent",
                    severity="HIGH",
                    line_number=line_num,
                    code_snippet=snippet,
                    description=(
                        f"AI agent is configured with {len(dangerous_ops_found)} dangerous "
                        f"operations: {', '.join(sorted(dangerous_ops_found))}. "
                        f"This violates the principle of least privilege. If an attacker "
                        f"achieves prompt injection, they could abuse these permissions to "
                        f"cause significant damage. Consider implementing: "
                        f"1) Tool access controls, 2) Human-in-the-loop approval for "
                        f"dangerous operations, 3) Read-only alternatives where possible."
                    ),
                    confidence=0.95,
                    cwe_id="CWE-269",
                    owasp_category="A01:2021 – Broken Access Control",
                    metadata={
                        'dangerous_operations_count': len(dangerous_ops_found),
                        'operations': list(dangerous_ops_found),
                        'detection_type': 'structured_analysis'
                    }
                )
                
                findings.append(finding)
                logger.info(
                    f"✓ Detected overprivileged agent at {file_name}:{line_num} "
                    f"({len(dangerous_ops_found)} dangerous ops)"
                )
        
        return findings
    
    def _analyze_permission_configs(self, code: str, file_name: str) -> List[Finding]:
        """
        Analyze configuration dictionaries for dangerous permissions.
        
        Detects patterns like:
        - "shell": True
        - "filesystem": ["read", "write", "delete"]
        - permissions granting destructive access
        
        Args:
            code: Full source code
            file_name: Name of the file
        
        Returns:
            List of findings for dangerous configs
        """
        findings = []
        lines = code.split('\n')
        
        # Dangerous permission patterns in config dictionaries
        dangerous_config_patterns = [
            # Shell access enabled
            (r'["\']shell["\']\s*:\s*True', 'Shell Access', 
             'Shell access enabled - allows arbitrary command execution'),
            
            # Delete permissions in lists
            (r'["\'](?:filesystem|permissions|tools)["\']\s*:\s*\[.*?["\']delete["\'].*?\]',
             'Delete Permission',
             'Delete permission granted - allows file/data destruction'),
            
            # Write + Delete combo (very dangerous)
            (r'\[.*?["\']write["\'].*?["\']delete["\'].*?\]',
             'Write+Delete Permissions',
             'Both write and delete permissions - high risk for data loss'),
            
            # Admin/root/sudo access
            (r'["\'](?:admin|root|sudo|elevated)["\']?\s*:\s*True',
             'Elevated Privileges',
             'Elevated/admin privileges enabled'),
            
            # Execute permissions
            (r'["\'](?:execute|exec|run)["\']?\s*:\s*True',
             'Execute Permission',
             'Code execution permission enabled'),
            
            # Full access patterns
            (r'["\'](?:full_access|all_permissions|unrestricted)["\']?\s*:\s*True',
             'Unrestricted Access',
             'Unrestricted/full access granted'),
        ]
        
        # Track config blocks
        in_config = False
        config_start = 0
        brace_count = 0
        config_content = []
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Detect start of config function or dict
            if re.search(r'def\s+config\s*\(|["\']?(?:config|settings|permissions)["\']?\s*[=:]\s*\{', line):
                in_config = True
                config_start = line_num
                brace_count = line.count('{') - line.count('}')
                config_content = [line]
                continue
            
            if in_config:
                config_content.append(line)
                brace_count += line.count('{') - line.count('}')
                
                # Check if config block ended
                if brace_count <= 0 or (stripped.startswith('def ') and line_num > config_start):
                    in_config = False
                    full_config = '\n'.join(config_content)
                    
                    # Check for dangerous patterns in the config
                    dangers_found = []
                    for pattern, danger_type, description in dangerous_config_patterns:
                        if re.search(pattern, full_config, re.IGNORECASE | re.DOTALL):
                            dangers_found.append((danger_type, description))
                    
                    if dangers_found:
                        snippet = self.extract_code_snippet(code, config_start, context_lines=5)
                        
                        danger_summary = ', '.join([d[0] for d in dangers_found])
                        
                        finding = Finding(
                            detector_name=self.name,
                            vulnerability_type="Overly Permissive AI Config",
                            severity="HIGH",
                            line_number=config_start,
                            code_snippet=snippet,
                            description=(
                                f"Configuration grants dangerous permissions: {danger_summary}. "
                                f"Details: {'; '.join([d[1] for d in dangers_found])}. "
                                f"AI agents and tools should follow least privilege principle. "
                                f"Granting shell access or delete permissions allows attackers "
                                f"to cause severe damage via prompt injection attacks."
                            ),
                            confidence=0.90,
                            cwe_id="CWE-269",
                            owasp_category="A01:2021 – Broken Access Control",
                            metadata={
                                'detection_type': 'permission_config',
                                'dangers_found': [d[0] for d in dangers_found],
                                'config_start_line': config_start
                            }
                        )
                        
                        findings.append(finding)
                        logger.info(
                            f"✓ Detected overly permissive config at {file_name}:{config_start} "
                            f"({len(dangers_found)} dangerous permissions)"
                        )
                    
                    config_content = []
            
            # Also check individual lines for dangerous patterns (outside config blocks)
            for pattern, danger_type, description in dangerous_config_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Avoid duplicate with config block detection
                    if not in_config:
                        snippet = self.extract_code_snippet(code, line_num, context_lines=2)
                        
                        finding = Finding(
                            detector_name=self.name,
                            vulnerability_type="Dangerous Permission Setting",
                            severity="HIGH",
                            line_number=line_num,
                            code_snippet=snippet,
                            description=(
                                f"Dangerous permission detected: {danger_type}. {description}. "
                                f"This setting could allow attackers to abuse the system "
                                f"through prompt injection or other attacks."
                            ),
                            confidence=0.85,
                            cwe_id="CWE-269",
                            owasp_category="A01:2021 – Broken Access Control",
                            metadata={
                                'detection_type': 'inline_permission',
                                'danger_type': danger_type
                            }
                        )
                        
                        findings.append(finding)
                        logger.info(
                            f"✓ Detected dangerous permission at {file_name}:{line_num} "
                            f"({danger_type})"
                        )
                        break
        
        return findings


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    detector = OverprivilegedToolsDetector()
    
    # Example vulnerable code
    test_code = '''
from langchain.agents import initialize_agent
from langchain.tools import Tool

# VULNERABLE: AI agent with delete permissions
tools = [
    Tool(name="delete_file", func=delete_file),
    Tool(name="execute_command", func=subprocess.run),
    Tool(name="drop_table", func=drop_database_table)
]

agent = initialize_agent(tools=tools, llm=llm, agent="zero-shot-react")
    '''
    
    findings = detector.detect(test_code, 'python', 'test.py')
    print(f"Found {len(findings)} overprivileged tool issues")

