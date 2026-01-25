"""
Unified Snowflake Setup Script
Combines schema setup (Tables/Views) and RAG setup (Vector Database).
"""

import os
import snowflake.connector
from dotenv import load_dotenv
from pathlib import Path
import time

# Load environment variables
load_dotenv()

def get_snowflake_connection():
    """Establish and return a Snowflake connection."""
    return snowflake.connector.connect(
        account=os.getenv('SNOWFLAKE_ACCOUNT'),
        user=os.getenv('SNOWFLAKE_USER'),
        password=os.getenv('SNOWFLAKE_PASSWORD'),
        role=os.getenv('SNOWFLAKE_ROLE', 'ACCOUNTADMIN'),
        warehouse=os.getenv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH")
    )

def setup_general_schema(conn, sql_file_path: str):
    """
    Execute the general SQL schema file (Tables, Views).
    """
    print("\n" + "=" * 50)
    print("🏗️  Setting up General Schema (Tables & Views)")
    print("=" * 50)
    
    cursor = conn.cursor()
    try:
        print(f"📄 Reading SQL file: {sql_file_path}")
        with open(sql_file_path, 'r') as f:
            sql_content = f.read()
        
        # Parse statements
        statements = [stmt.strip() for stmt in sql_content.split(';') if stmt.strip()]
        
        print(f"🚀 Executing {len(statements)} statements...")
        
        errors = []
        for i, statement in enumerate(statements, 1):
            if not statement or statement.startswith('--'): continue
            try:
                cursor.execute(statement)
                print(f"  ✓ Statement {i} success")
            except Exception as e:
                errors.append(f"Statement {i}: {e}")
                print(f"  ⚠️  Statement {i} failed: {e}")
                
        if errors:
            print(f"⚠️  Schema setup completed with {len(errors)} errors.")
        else:
            print("✅ General Schema setup complete.")
            
    except Exception as e:
        print(f"❌ Schema setup failed: {e}")
        raise
    finally:
        cursor.close()

def setup_rag_schema(conn):
    """
    Sets up the RAG infrastructure (Vector Database).
    """
    print("\n" + "=" * 50)
    print("🧠  Setting up RAG Infrastructure (Vector DB)")
    print("=" * 50)
    
    cursor = conn.cursor()
    try:
        # 1. Create Database (Idempotent)
        print("... Verifying Database LLMCHECK_DB")
        cursor.execute("CREATE DATABASE IF NOT EXISTS LLMCHECK_DB")
        
        # 2. Create Schema
        print("... Verifying Schema RAG")
        cursor.execute("CREATE SCHEMA IF NOT EXISTS LLMCHECK_DB.RAG")
        
        # 3. Create Vector Table
        print("... Verifying Table DOCUMENT_CHUNKS (Vector: 768)")
        create_table_query = """
        CREATE TABLE IF NOT EXISTS LLMCHECK_DB.RAG.DOCUMENT_CHUNKS (
            ID VARCHAR(36) DEFAULT UUID_STRING(),
            CHUNK_TEXT VARCHAR,
            EMBEDDING VECTOR(FLOAT, 768),
            SOURCE_FILE VARCHAR,
            CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
        )
        """
        cursor.execute(create_table_query)
        
        # 4. Enable Change Tracking
        try:
            cursor.execute("ALTER TABLE LLMCHECK_DB.RAG.DOCUMENT_CHUNKS SET CHANGE_TRACKING = TRUE")
            print("... Change Tracking Enabled")
        except Exception:
            pass # Might already be on

        print("✅ RAG Infrastructure setup complete.")
        
    except Exception as e:
        print(f"❌ RAG setup failed: {e}")
        raise
    finally:
        cursor.close()

def main():
    print("\n" + "=" * 70)
    print("❄️  Unified LLMCheck Snowflake Setup")
    print("=" * 70)
    
    # Check SQL file
    sql_file = Path(__file__).parent / 'config' / 'snowflake_schema.sql'
    if not sql_file.exists():
        print(f"❌ Config file not found: {sql_file}")
        return

    # Check Env
    required_vars = ['SNOWFLAKE_ACCOUNT', 'SNOWFLAKE_USER', 'SNOWFLAKE_PASSWORD']
    missing = [v for v in required_vars if not os.getenv(v)]
    if missing:
        print(f"❌ Missing environment variables: {', '.join(missing)}")
        return

    # Confirm
    print(f"Target Account: {os.getenv('SNOWFLAKE_ACCOUNT')}")
    if input("\n⚠️  Proceed with Database Setup? (y/n): ").lower() != 'y':
        print("Cancelled.")
        return

    try:
        conn = get_snowflake_connection()
        print("✓ Connected to Snowflake")
        
        # Run Setup Phases
        setup_general_schema(conn, str(sql_file))
        setup_rag_schema(conn)
        
        print("\n" + "=" * 70)
        print("🎉 All Setup Tasks Completed Successfully!")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ Critical Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    main()
