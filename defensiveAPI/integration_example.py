def main():
    """Complete security testing integration example"""
    
    # 1. Load configuration
    config = SnowflakeConfig(
        account="your-account",
        user="security_tester",
        password="test_password",  # Use environment variables in production!
        warehouse="TEST_WH",
        database="SECURITY_TEST_DB",
        schema="TEST_SCHEMA",
        role="SECURITY_TEST_ROLE"
    )
    
    # 2. Create secure API instance
    snowflake_api = SecureSnowflakeAPI(config, enable_security_tests=True)
    
    if not snowflake_api.connect():
        print("Failed to connect to Snowflake")
        return
    
    # 3. Initialize security tester
    security_tester = SnowflakeSecurityTester(snowflake_api)
    
    # 4. Run security test suite
    print("Running security tests...")
    security_report = security_tester.run_security_test_suite()
    
    # 5. Display results
    print("\n" + "="*60)
    print("SECURITY TEST REPORT")
    print("="*60)
    
    summary = security_report["summary"]
    print(f"\nSummary:")
    print(f"  Total Tests: {summary['total_tests']}")
    print(f"  Passed: {summary['passed']}")
    print(f"  Failed: {summary['failed']}")
    print(f"  Warnings: {summary['warnings']}")
    print(f"  Security Score: {summary['score']:.1f}%")
    
    # 6. Show failed tests
    if summary['failed'] > 0:
        print(f"\n⚠️  FAILED TESTS:")
        for result in security_report["detailed_results"]:
            if result.get("status") == "failed":
                print(f"  - {result['test']}")
                if "details" in result:
                    print(f"    Details: {result['details']}")
    
    # 7. Show recommendations
    if security_report["recommendations"]:
        print(f"\n🔧 RECOMMENDATIONS:")
        for rec in security_report["recommendations"]:
            print(f"  [{rec['priority'].upper()}] {rec['issue']}: {rec['recommendation']}")
    
    # 8. Run sample queries with security monitoring
    print("\n" + "="*60)
    print("TESTING SAMPLE QUERIES WITH SECURITY MONITORING")
    print("="*60)
    
    monitor = SecurityMonitor(snowflake_api)
    
    # Test queries
    test_queries = [
        ("SELECT * FROM test_table WHERE id = %s", (1,)),
        ("SELECT * FROM users WHERE username = 'admin' --", None),  # Suspicious
        ("SELECT * FROM large_table LIMIT 15000", None),  # Large data export
    ]
    
    for query, params in test_queries:
        print(f"\nQuery: {query}")
        result = snowflake_api.execute_query(query, params)
        monitor.monitor_query(query, params, result)
        
        if result["success"]:
            print(f"  ✓ Success: {result['row_count']} rows returned")
        else:
            print(f"  ✗ Failed: {result.get('error', 'Unknown error')}")
        
        # Check security metadata
        if "security_issue" in result:
            print(f"  ⚠️  Security issue detected: {result['security_issue']}")
    
    # 9. Show security alerts
    if monitor.suspicious_activities:
        print(f"\n🚨 SECURITY ALERTS GENERATED:")
        for alert in monitor.suspicious_activities:
            print(f"  - {alert['type']} (Severity: {alert['severity']})")

if __name__ == "__main__":
    main()