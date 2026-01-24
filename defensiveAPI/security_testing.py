"""
SNOWFLAKE API SECURITY TESTING INTEGRATION
This connects security tests to your actual Snowflake API endpoints
"""

# Try to import snowflake connector, but don't fail if not available
try:
    import snowflake.connector
    SNOWFLAKE_AVAILABLE = True
except ImportError:
    SNOWFLAKE_AVAILABLE = False
    snowflake = None

import json
import logging
from typing import Dict, Any, Optional
import re
from dataclasses import dataclass
from abc import ABC, abstractmethod

# Configure logging for security events
security_logger = logging.getLogger('security_testing')
security_logger.setLevel(logging.INFO)

@dataclass
class SnowflakeConfig:
    """Secure configuration for Snowflake connection"""
    account: str
    user: str
    password: str  # In production, use environment variables or secret manager
    warehouse: str
    database: str
    schema: str
    role: str
    
    @classmethod
    def from_env(cls):
        """Load configuration from environment variables"""
        import os
        return cls(
            account=os.getenv('SNOWFLAKE_ACCOUNT'),
            user=os.getenv('SNOWFLAKE_USER'),
            password=os.getenv('SNOWFLAKE_PASSWORD'),
            warehouse=os.getenv('SNOWFLAKE_WAREHOUSE'),
            database=os.getenv('SNOWFLAKE_DATABASE'),
            schema=os.getenv('SNOWFLAKE_SCHEMA'),
            role=os.getenv('SNOWFLAKE_ROLE')
        )