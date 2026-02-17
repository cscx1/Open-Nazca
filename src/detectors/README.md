# Detectors

Vulnerability detectors used by the scanner. Each module implements the `BaseDetector` interface and returns `Finding` objects.

## By category (for organization / principle-based roadmap)

| Category | Detectors | Principle |
|----------|-----------|-----------|
| **Injection** | `prompt_injection_detector`, `sql_injection_detector`, `xss_detector`, `ldap_injection_detector`, `xpath_injection_detector`, `log_injection_detector` | Untrusted data must not control syntax or interpretation |
| **Crypto / randomness** | `crypto_misuse_detector`, `weak_hash_detector`, `weak_random_detector` | Use strong crypto and secure randomness |
| **Data handling** | `deserialization_detector`, `xxe_detector` | Unsafe deserialization and XML parsing |
| **Access / trust** | `overprivileged_tools_detector`, `trust_boundary_detector`, `secure_cookie_detector` | Least privilege and trust boundaries |
| **Secrets** | `hardcoded_secrets_detector` | No credentials in source |
| **Operational / robustness** | `operational_security_detector`, `toctou_detector`, `memory_safety_detector`, `type_confusion_detector`, `evasion_patterns_detector` | Safe operations and robustness |
| **Reflection / flow** | `unsafe_reflection_detector`, `general_flow_detector` | Safe use of reflection and data flow |

## Base and helpers

- **base_detector.py** — `BaseDetector` ABC and `Finding` dataclass; all detectors inherit from it.
- **vuln_ownership.py** — Helper (not in scanner’s default detector list).

## Loading

The scanner loads detectors from `src.detectors` via `__init__.py`. Adding a new detector requires:

1. Implement a class that extends `BaseDetector` and implements `detect()`.
2. Register it in `src/detectors/__init__.py` (import and add to `__all__`).
3. The scanner will instantiate and run it automatically.

## Future: principle-based verdict layer

When adding a security model and verdict layer (context + app type + “real vs false positive”), detectors can stay as-is; the verdict layer will consume their findings and map them to the categories above for consistent interpretation.
