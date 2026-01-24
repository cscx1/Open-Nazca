class SnowflakeSecurityTester:
    """Integrated security testing for Snowflake API"""
    
    def __init__(self, snowflake_api: SecureSnowflakeAPI = None):
        self.api = snowflake_api
        self.test_results = []
        
    def run_security_test_suite(self):
        """Run comprehensive security tests"""
        tests = [
            self.test_sql_injection_resistance,
            self.test_privilege_escalation,
            self.test_data_leakage,
            self.test_authentication_bypass,
            self.test_side_channel_leaks
        ]
        
        results = []
        for test in tests:
            try:
                result = test()
                results.append(result)
                self._log_test_result(result)
            except Exception as e:
                results.append({
                    "test": test.__name__,
                    "status": "error",
                    "error": str(e)
                })
        
        return self._generate_security_report(results)
    
    def test_sql_injection_resistance(self) -> Dict[str, Any]:
        """Test SQL injection resistance"""
        if not self.api:
            return {"test": "SQL Injection", "status": "skipped", "reason": "No API connection"}
        
        injection_attempts = [
            ("SELECT * FROM users WHERE id = %s", ("1 OR 1=1",)),
            ("SELECT * FROM products WHERE name = %s", ("'; DROP TABLE products --",)),
            ("SELECT * FROM orders WHERE user_id = %s", ("1 UNION SELECT password FROM users",)),
        ]
        
        results = []
        for query, params in injection_attempts:
            result = self.api.execute_query(query, params, validate_input=True)
            results.append({
                "query": query,
                "params": params,
                "success": result["success"],
                "blocked": "security_issue" in result
            })
        
        return {
            "test": "SQL Injection Resistance",
            "status": "passed" if all(r["blocked"] for r in results) else "failed",
            "details": results
        }
    
    def test_privilege_escalation(self) -> Dict[str, Any]:
        """Test for privilege escalation attempts"""
        if not self.api:
            return {"test": "Privilege Escalation", "status": "skipped"}
        
        # Try to access system tables
        privileged_queries = [
            "SELECT * FROM information_schema.tables",
            "SHOW USERS",
            "SHOW ROLES",
            "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY"
        ]
        
        results = []
        for query in privileged_queries:
            result = self.api.execute_query(query, validate_input=True)
            results.append({
                "query": query,
                "access_granted": result["success"],
                "rows_returned": result.get("row_count", 0) if result["success"] else 0
            })
        
        # Check if user has excessive privileges
        excessive_privileges = sum(1 for r in results if r["access_granted"])
        
        return {
            "test": "Privilege Escalation",
            "status": "passed" if excessive_privileges == 0 else "warning",
            "details": results,
            "recommendation": "Review user role privileges" if excessive_privileges > 0 else None
        }
    
    def test_data_leakage(self) -> Dict[str, Any]:
        """Test for data leakage in error messages"""
        if not self.api:
            return {"test": "Data Leakage", "status": "skipped"}
        
        # Test queries that should fail
        test_queries = [
            "SELECT * FROM nonexistent_table",
            "SELECT column_that_doesnt_exist FROM users",
            "INSERT INTO invalid_schema.table VALUES (1)"
        ]
        
        results = []
        for query in test_queries:
            result = self.api.execute_query(query, validate_input=False)
            results.append({
                "query": query,
                "error_exposed": "snowflake" in result.get("error", "").lower() or 
                                "line" in result.get("error", "").lower(),
                "error_message": result.get("error", "")[:100]  # First 100 chars only
            })
        
        sensitive_leakage = sum(1 for r in results if r["error_exposed"])
        
        return {
            "test": "Data Leakage Prevention",
            "status": "passed" if sensitive_leakage == 0 else "failed",
            "details": results,
            "recommendation": "Implement generic error messages" if sensitive_leakage > 0 else None
        }
    
    def test_side_channel_leaks(self) -> Dict[str, Any]:
        """Test for timing-based side channel leaks"""
        import time
        
        # Test timing differences in authentication
        valid_user = "test_user"
        invalid_user = "nonexistent_user"
        
        timing_results = []
        
        for username in [valid_user, invalid_user]:
            start = time.perf_counter_ns()
            # Simulate authentication check
            query = "SELECT 1 FROM users WHERE username = %s"
            if self.api:
                result = self.api.execute_query(query, (username,))
            end = time.perf_counter_ns()
            
            timing_results.append({
                "username": username,
                "time_ns": end - start
            })
        
        # Check if timing difference reveals user existence
        time_diff = abs(timing_results[0]["time_ns"] - timing_results[1]["time_ns"])
        
        return {
            "test": "Side Channel Timing Attack",
            "status": "warning" if time_diff > 1000000 else "passed",  # 1ms threshold
            "timing_difference_ns": time_diff,
            "details": timing_results,
            "recommendation": "Implement constant-time authentication" if time_diff > 1000000 else None
        }
    
    def _log_test_result(self, result: Dict[str, Any]):
        """Log security test result"""
        security_logger.info(f"Security test: {result['test']} - {result['status']}")
        self.test_results.append(result)
    
    def _generate_security_report(self, results: list) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        passed = sum(1 for r in results if r.get("status") == "passed")
        failed = sum(1 for r in results if r.get("status") == "failed")
        warnings = sum(1 for r in results if r.get("status") == "warning")
        
        return {
            "summary": {
                "total_tests": len(results),
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "score": (passed / len(results)) * 100 if results else 0
            },
            "detailed_results": results,
            "timestamp": self._get_timestamp(),
            "recommendations": self._generate_recommendations(results)
        }
    
    def _generate_recommendations(self, results: list) -> list:
        """Generate security recommendations from test results"""
        recommendations = []
        
        for result in results:
            if result.get("status") in ["failed", "warning"] and "recommendation" in result:
                recommendations.append({
                    "issue": result["test"],
                    "recommendation": result["recommendation"],
                    "priority": "high" if result["status"] == "failed" else "medium"
                })
        
        return recommendations