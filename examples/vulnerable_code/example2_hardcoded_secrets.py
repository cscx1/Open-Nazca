"""
Example 2: Hardcoded Secrets Vulnerabilities
This file contains intentional security vulnerabilities for demonstration purposes.
DO NOT USE THIS CODE IN PRODUCTION!
"""

import requests
import boto3

# VULNERABLE: Hardcoded API keys
OPENAI_API_KEY = "sk-proj1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
ANTHROPIC_API_KEY = "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"

# VULNERABLE: AWS credentials in code
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABLE: Database credentials
DB_PASSWORD = "MyS3cretP@ssw0rd123!"
DATABASE_CONNECTION = "postgresql://admin:SuperSecret123@db.example.com:5432/mydb"

# VULNERABLE: API tokens
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz123"
SLACK_TOKEN = "xoxb-FAKE-TOKEN-FOR-DEMO-ONLY-abcdefghijk"  # Intentionally fake


def call_openai_vulnerable():
    """
    VULNERABLE: Using hardcoded API key
    """
    import openai
    
    # BAD: API key hardcoded
    openai.api_key = OPENAI_API_KEY
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )
    
    return response


def access_aws_vulnerable():
    """
    VULNERABLE: Hardcoded AWS credentials
    """
    # BAD: Credentials in code
    client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    
    return client.list_buckets()


def connect_database_vulnerable():
    """
    VULNERABLE: Database password in connection string
    """
    import psycopg2
    
    # BAD: Password in connection string
    conn = psycopg2.connect(
        host="db.example.com",
        database="mydb",
        user="admin",
        password=DB_PASSWORD  # Hardcoded password
    )
    
    return conn


# SAFE ALTERNATIVES (for comparison):
def call_openai_safe():
    """
    SAFE: Using environment variables
    """
    import os
    import openai
    
    # GOOD: Load from environment
    openai.api_key = os.getenv('OPENAI_API_KEY')
    
    if not openai.api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )
    
    return response


def access_aws_safe():
    """
    SAFE: Using AWS credentials from environment/IAM role
    """
    # GOOD: boto3 automatically uses credentials from:
    # 1. Environment variables
    # 2. ~/.aws/credentials
    # 3. IAM role (if on EC2/Lambda)
    client = boto3.client('s3')
    
    return client.list_buckets()


def connect_database_safe():
    """
    SAFE: Using environment variables for database connection
    """
    import os
    import psycopg2
    
    # GOOD: Load from environment
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST'),
        database=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD')
    )
    
    return conn


if __name__ == "__main__":
    print("This file demonstrates hardcoded secret vulnerabilities.")
    print("Never commit real API keys or passwords to version control!")

