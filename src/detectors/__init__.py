"""Vulnerability detection modules for AI code security scanning."""

from .base_detector import BaseDetector, Finding
from .prompt_injection_detector import PromptInjectionDetector
from .hardcoded_secrets_detector import HardcodedSecretsDetector
from .overprivileged_tools_detector import OverprivilegedToolsDetector
from .weak_random_detector import WeakRandomDetector
from .weak_hash_detector import WeakHashDetector
from .xpath_injection_detector import XPathInjectionDetector
from .xxe_detector import XXEDetector
from .sql_injection_detector import SQLInjectionDetector
from .deserialization_detector import DeserializationDetector
from .secure_cookie_detector import SecureCookieDetector
from .trust_boundary_detector import TrustBoundaryDetector
from .ldap_injection_detector import LDAPInjectionDetector
from .general_flow_detector import GeneralFlowDetector
from .unsafe_reflection_detector import UnsafeReflectionDetector
from .crypto_misuse_detector import CryptoMisuseDetector
from .toctou_detector import TOCTOUDetector
from .memory_safety_detector import MemorySafetyDetector
from .type_confusion_detector import TypeConfusionDetector
from .log_injection_detector import LogInjectionDetector
from .xss_detector import XSSDetector
from .evasion_patterns_detector import EvasionPatternsDetector
from .operational_security_detector import OperationalSecurityDetector

__all__ = [
    'BaseDetector',
    'Finding',
    'PromptInjectionDetector',
    'HardcodedSecretsDetector',
    'OverprivilegedToolsDetector',
    'WeakRandomDetector',
    'WeakHashDetector',
    'XPathInjectionDetector',
    'XXEDetector',
    'SQLInjectionDetector',
    'DeserializationDetector',
    'SecureCookieDetector',
    'TrustBoundaryDetector',
    'LDAPInjectionDetector',
    'GeneralFlowDetector',
    'UnsafeReflectionDetector',
    'CryptoMisuseDetector',
    'TOCTOUDetector',
    'MemorySafetyDetector',
    'TypeConfusionDetector',
    'LogInjectionDetector',
    'XSSDetector',
    'EvasionPatternsDetector',
    'OperationalSecurityDetector',
]

