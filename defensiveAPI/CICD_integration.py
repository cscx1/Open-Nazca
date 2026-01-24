# security_test_ci.py
import sys
import json

def run_security_tests_in_ci():
    """
    Run security tests as part of CI/CD pipeline
    Returns exit code 0 for passed, 1 for failed
    """
    
    # This would be called by your CI/CD system
    config = SnowflakeConfig.from_env()  # Load from CI environment
    
    api = SecureSnowflakeAPI(config)
    if not api.connect():
        print("❌ Failed to connect to Snowflake")
        return 1
    
    tester = SnowflakeSecurityTester(api)
    report = tester.run_security_test_suite()
    
    # Save report to file
    with open('security_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    # Check for critical failures
    if report["summary"]["failed"] > 0:
        print("❌ Critical security test failures detected!")
        print("Failing tests:")
        for result in report["detailed_results"]:
            if result.get("status") == "failed":
                print(f"  - {result['test']}")
        return 1  # Fail the build
    
    elif report["summary"]["warnings"] > 0:
        print("⚠️  Security warnings detected (build passes with warnings)")
        return 0
    
    else:
        print("✅ All security tests passed!")
        return 0

# Example GitHub Actions workflow snippet:
"""
name: Security Testing
on: [push, pull_request]

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
    - name: Install dependencies
      run: |
        pip install snowflake-connector-python
    - name: Run security tests
      env:
        SNOWFLAKE_ACCOUNT: ${{ secrets.SNOWFLAKE_ACCOUNT }}
        SNOWFLAKE_USER: ${{ secrets.SNOWFLAKE_USER }}
        SNOWFLAKE_PASSWORD: ${{ secrets.SNOWFLAKE_PASSWORD }}
      run: |
        python security_test_ci.py
    - name: Upload security report
      uses: actions/upload-artifact@v2
      with:
        name: security-report
        path: security_report.json
"""