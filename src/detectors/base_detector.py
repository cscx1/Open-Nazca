"""
Base Detector Class for AI Code Breaker
Provides common interface for all vulnerability detectors.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """
    Represents a single security vulnerability finding.
    """
    detector_name: str
    vulnerability_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    line_number: Optional[int]
    code_snippet: str
    description: str
    confidence: float = 1.0
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    metadata: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        """Convert finding to dictionary for storage."""
        return {
            'detector_name': self.detector_name,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'description': self.description,
            'confidence': self.confidence,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'metadata': self.metadata or {}
        }


class BaseDetector(ABC):
    """
    Abstract base class for all vulnerability detectors.
    Each detector implements specific security checks.
    """
    
    def __init__(self, name: str, enabled: bool = True):
        """
        Initialize detector.
        
        Args:
            name: Name of the detector
            enabled: Whether detector is enabled
        """
        self.name = name
        self.enabled = enabled
        self.findings: List[Finding] = []
    
    @abstractmethod
    def detect(self, code: str, language: str, file_name: str) -> List[Finding]:
        """
        Main detection method to be implemented by each detector.
        
        Args:
            code: Source code to analyze
            language: Programming language
            file_name: Name of the file being analyzed
        
        Returns:
            List of Finding objects
        """
        pass
    
    def get_line_number(self, code: str, pattern: str, occurrence: int = 0) -> Optional[int]:
        """
        Find line number of a pattern in code.
        
        Args:
            code: Source code
            pattern: Pattern to find
            occurrence: Which occurrence to find (0-indexed)
        
        Returns:
            Line number (1-indexed) or None
        """
        lines = code.split('\n')
        count = 0
        
        for i, line in enumerate(lines, 1):
            if pattern in line:
                if count == occurrence:
                    return i
                count += 1
        
        return None
    
    def extract_code_snippet(
        self,
        code: str,
        line_number: int,
        context_lines: int = 4
    ) -> str:
        """
        Extract code snippet around a specific line.
        
        Args:
            code: Full source code
            line_number: Center line number
            context_lines: Number of lines to include before/after
        
        Returns:
            Code snippet as string with line numbers
        """
        lines = code.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines + 1)
        
        snippet_lines = []
        for i in range(start, end):
            line_num = i + 1
            marker = " → " if line_num == line_number else "   "
            snippet_lines.append(f"{line_num:3d}{marker}| {lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def reset_findings(self):
        """Clear all findings."""
        self.findings = []
    
    def get_findings_count(self) -> int:
        """Get number of findings."""
        return len(self.findings)
    
    def __repr__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"{self.__class__.__name__}(name='{self.name}', {status})"

