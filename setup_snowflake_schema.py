"""
Snowflake Schema Setup Script
Executes the snowflake_schema.sql file to create database, tables, and views.
"""

import os
import snowflake.connector
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()

def execute_sql_file(sql_file_path: str):
    """
    Execute a SQL file against Snowflake.
    
    Args:
        sql_file_path: Path to SQL file
    """
    print("🔗 Connecting to Snowflake...")
    
    # Connect to Snowflake
    conn = snowflake.connector.connect(
        account=os.getenv('SNOWFLAKE_ACCOUNT'),
        user=os.getenv('SNOWFLAKE_USER'),
        password=os.getenv('SNOWFLAKE_PASSWORD'),
        role=os.getenv('SNOWFLAKE_ROLE', 'ACCOUNTADMIN')
    )
    
    cursor = conn.cursor()
    
    try:
        print(f"✓ Connected to Snowflake account: {os.getenv('SNOWFLAKE_ACCOUNT')}")
        print(f"\n📄 Reading SQL file: {sql_file_path}")
        
        # Read SQL file
        with open(sql_file_path, 'r') as f:
            sql_content = f.read()
        
        # Remove comment lines (lines starting with --)
        lines = sql_content.split('\n')
        sql_lines_no_comments = []
        for line in lines:
            # Remove inline comments and empty lines
            stripped = line.strip()
            if not stripped.startswith('--'):
                sql_lines_no_comments.append(line)
        
        sql_content_clean = '\n'.join(sql_lines_no_comments)
        
        # Split into individual statements (by semicolon)
        statements = [stmt.strip() for stmt in sql_content_clean.split(';') if stmt.strip()]
        
        print(f"✓ Found {len(statements)} SQL statements\n")
        print("=" * 70)
        print("🚀 Executing SQL statements...")
        print("=" * 70)
        
        # Track errors
        errors = []
        
        # Execute each statement
        for i, statement in enumerate(statements, 1):
            # Skip comments and empty statements
            statement_clean = statement.strip()
            if not statement_clean or statement_clean.startswith('--'):
                print(f"[{i}/{len(statements)}] Skipping comment/empty")
                continue
            
            try:
                # Print first 100 chars of statement for visibility
                preview = statement_clean[:100].replace('\n', ' ')
                print(f"\n[{i}/{len(statements)}] Executing: {preview}...")
                
                cursor.execute(statement)
                
                print(f"✓ Success")
                
            except Exception as e:
                error_msg = f"Statement {i}: {str(e)}"
                errors.append(error_msg)
                print(f"⚠️  Warning: {e}")
                # Continue instead of raising
        
        print("\n" + "=" * 70)
        
        if errors:
            print(f"⚠️  Completed with {len(errors)} error(s):")
            for error in errors:
                print(f"  - {error}")
            print("=" * 70)
        else:
            print("✅ All statements executed successfully!")
            print("=" * 70)
        
        # Verify tables were created
        print("\n🔍 Verifying schema setup...")
        
        cursor.execute("USE DATABASE LLMCHECK_DB")
        cursor.execute("USE SCHEMA PUBLIC")
        
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        
        print(f"\n✓ Created {len(tables)} tables:")
        for table in tables:
            print(f"  - {table[1]}")  # table[1] is the table name
        
        cursor.execute("SHOW VIEWS")
        views = cursor.fetchall()
        
        if views:
            print(f"\n✓ Created {len(views)} views:")
            for view in views:
                print(f"  - {view[1]}")
        
        print("\n✅ Snowflake schema setup complete!")
        
    except Exception as e:
        print(f"\n❌ Failed to execute SQL: {e}")
        raise
        
    finally:
        cursor.close()
        conn.close()
        print("\n🔒 Connection closed")


if __name__ == "__main__":
    # Path to SQL schema file
    sql_file = Path(__file__).parent / 'config' / 'snowflake_schema.sql'
    
    if not sql_file.exists():
        print(f"❌ SQL file not found: {sql_file}")
        exit(1)
    
    print("\n" + "=" * 70)
    print("🏗️  LLMCheck Snowflake Schema Setup")
    print("=" * 70)
    print(f"\nSQL File: {sql_file}")
    print(f"Account: {os.getenv('SNOWFLAKE_ACCOUNT')}")
    print(f"User: {os.getenv('SNOWFLAKE_USER')}")
    print(f"Role: {os.getenv('SNOWFLAKE_ROLE', 'ACCOUNTADMIN')}")
    
    # Confirm before executing
    response = input("\n⚠️  This will create/modify Snowflake objects. Continue? (yes/no): ")
    
    if response.lower() in ['yes', 'y']:
        execute_sql_file(str(sql_file))
    else:
        print("\n❌ Setup cancelled by user")
