"""Vulnerability detection modules for AI code security scanning."""

from .base_detector import BaseDetector, Finding
from .prompt_injection_detector import PromptInjectionDetector
from .hardcoded_secrets_detector import HardcodedSecretsDetector
from .overprivileged_tools_detector import OverprivilegedToolsDetector

__all__ = [
    'BaseDetector',
    'Finding',
    'PromptInjectionDetector',
    'HardcodedSecretsDetector',
    'OverprivilegedToolsDetector',
]

