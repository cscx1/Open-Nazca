def create_security_lab():
    """Set up isolated environment for security education"""
    lab_config = {
        "environment": {
            "type": "Virtual Machines / Docker containers",
            "network": "Isolated VLAN, no internet access",
            "tools": [
                "Wireshark for traffic analysis",
                "OWASP ZAP for web testing",
                "Custom Python scripts",
                "Snowflake trial account"
            ]
        },
        "targets": [
            "Snowflake API simulator",
            "Custom web application frontend",
            "Mock authentication server",
            "Sample databases with dummy data"
        ],
        "rules": [
            "NO production systems",
            "NO real customer data",
            "Document all findings",
            "Immediate disclosure of critical issues"
        ]
    }
    return lab_config