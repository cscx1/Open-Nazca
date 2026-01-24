"""
Main entry point for running scanner as a module.
Usage: python -m src.scanner
"""

import sys
import logging
from pathlib import Path

from .scanner import AICodeScanner

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    if len(sys.argv) < 2:
        print("Usage: python -m src <file_to_scan>")
        print("\nExample:")
        print("  python -m src examples/vulnerable_code/example1_prompt_injection.py")
        print("\nFor more options, use the CLI:")
        print("  python cli.py --help")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not Path(file_path).exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    print("Initializing scanner...")
    scanner = AICodeScanner(
        use_snowflake=False,
        use_llm_analysis=False
    )
    
    print(f"Scanning {file_path}...")
    results = scanner.scan_file(file_path)
    
    if results['success']:
        print(f"\n✅ Scan complete! Found {results['total_findings']} vulnerabilities")
    else:
        print(f"\n❌ Scan failed: {results.get('error')}")
    
    scanner.close()

if __name__ == '__main__':
    main()

