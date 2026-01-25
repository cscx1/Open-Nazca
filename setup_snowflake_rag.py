import os
import snowflake.connector
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def setup_snowflake_rag():
    """
    Sets up the Snowflake infrastructure for RAG (Vector Database).
    Creates Database, Schema, and Vector Table.
    """
    print("❄️  Initializing Snowflake RAG Setup...")
    
    # Credentials
    user = os.getenv("SNOWFLAKE_USER")
    password = os.getenv("SNOWFLAKE_PASSWORD")
    account = os.getenv("SNOWFLAKE_ACCOUNT")
    warehouse = os.getenv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH")
    role = os.getenv("SNOWFLAKE_ROLE", "ACCOUNTADMIN")

    if not all([user, password, account]):
        print("❌ Error: Missing Snowflake credentials in .env file.")
        print("Required: SNOWFLAKE_USER, SNOWFLAKE_PASSWORD, SNOWFLAKE_ACCOUNT")
        return

    try:
        # Connect to Snowflake
        conn = snowflake.connector.connect(
            user=user,
            password=password,
            account=account,
            warehouse=warehouse,
            role=role
        )
        cursor = conn.cursor()
        print("✓ Connected to Snowflake")

        # 1. Create Database
        print("... Creating Database LLMCHECK_DB")
        cursor.execute("CREATE DATABASE IF NOT EXISTS LLMCHECK_DB")
        
        # 2. Create Schema
        print("... Creating Schema RAG")
        cursor.execute("CREATE SCHEMA IF NOT EXISTS LLMCHECK_DB.RAG")
        
        # 3. Create Vector Table
        # We use VECTOR(FLOAT, 768) to match 'snowflake-arctic-embed-m' dimension
        print("... Creating Table DOCUMENT_CHUNKS with VECTOR type")
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
        
        # 4. Enable Change Tracking (Optional, good for updates)
        cursor.execute("ALTER TABLE LLMCHECK_DB.RAG.DOCUMENT_CHUNKS SET CHANGE_TRACKING = TRUE")

        print("\n✅ Snowflake RAG Infrastructure Setup Complete!")
        print("---------------------------------------------")
        print("Database: LLMCHECK_DB")
        print("Schema:   RAG")
        print("Table:    DOCUMENT_CHUNKS")
        print("Vector:   768 dimensions (Arctic Embed M)")
        
    except Exception as e:
        print(f"\n❌ Setup Failed: {str(e)}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    setup_snowflake_rag()
