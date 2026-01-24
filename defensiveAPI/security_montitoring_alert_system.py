class SecurityMonitor:
    """Real-time security monitoring for Snowflake API"""
    
    def __init__(self, snowflake_api: SecureSnowflakeAPI):
        self.api = snowflake_api
        self.suspicious_activities = []
        self.alert_thresholds = {
            "failed_logins": 5,  # Alert after 5 failed attempts
            "sql_errors": 10,    # Alert after 10 SQL errors
            "large_queries": 3,  # Alert after 3 large data exports
        }
        self.counters = {
            "failed_logins": 0,
            "sql_errors": 0,
            "large_queries": 0
        }
    
    def monitor_query(self, query: str, params: tuple, result: Dict[str, Any]):
        """Monitor each query for suspicious patterns"""
        
        # Check for SQL injection patterns
        injection_score = self._calculate_injection_risk(query, params)
        if injection_score > 0.7:
            self._trigger_alert("potential_sql_injection", {
                "query": query,
                "score": injection_score,
                "timestamp": self._get_timestamp()
            })
        
        # Check for data exfiltration
        if result.get("success") and result.get("row_count", 0) > 10000:
            self.counters["large_queries"] += 1
            if self.counters["large_queries"] >= self.alert_thresholds["large_queries"]:
                self._trigger_alert("large_data_export", {
                    "row_count": result["row_count"],
                    "query": query[:200]  # First 200 chars only
                })
        
        # Check for authentication errors
        if not result.get("success") and "authentication" in result.get("error", "").lower():
            self.counters["failed_logins"] += 1
            if self.counters["failed_logins"] >= self.alert_thresholds["failed_logins"]:
                self._trigger_alert("brute_force_attempt", {
                    "failed_attempts": self.counters["failed_logins"]
                })
    
    def _calculate_injection_risk(self, query: str, params: tuple) -> float:
        """Calculate risk score for SQL injection"""
        risk_score = 0.0
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'(\-\-|\#)', 0.3),  # Comments
            (r'(;|\|\|)', 0.4),   # Statement separation
            (r'UNION', 0.6),      # UNION statements
            (r'SELECT.*SELECT', 0.5),  # Nested selects
            (r'(xp_|EXEC|EXECUTE)', 0.8),  # Procedure execution
        ]
        
        for pattern, score in suspicious_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                risk_score += score
        
        # Normalize to 0-1
        return min(1.0, risk_score)
    
    def _trigger_alert(self, alert_type: str, data: Dict[str, Any]):
        """Trigger security alert"""
        alert = {
            "type": alert_type,
            "data": data,
            "timestamp": self._get_timestamp(),
            "severity": self._get_severity(alert_type)
        }
        
        self.suspicious_activities.append(alert)
        
        # Log the alert
        security_logger.warning(f"Security alert: {alert_type} - {data}")
        
        # In production, you would:
        # 1. Send to SIEM system
        # 2. Trigger PagerDuty/Slack alert
        # 3. Block the IP/user if necessary
        
        return alert