#!/usr/bin/env python3
"""
Command-Line Interface for AI Code Breaker
Quick and easy security scanning from the terminal.
"""

import argparse
import sys
import logging
from pathlib import Path

from src.scanner import AICodeScanner


def setup_logging(verbose: bool = False):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    parser = argparse.ArgumentParser(
        description='🔒 Open Nazca - Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single file
  python cli.py scan examples/vulnerable_code/example1_prompt_injection.py
  
  # Scan with LLM analysis disabled (faster)
  python cli.py scan myfile.py --no-llm
  
  # Scan and store in Snowflake
  python cli.py scan myfile.py --snowflake
  
  # Scan a directory recursively
  python cli.py scan-dir ./myproject --recursive
  
  # Generate only HTML report
  python cli.py scan myfile.py --format html
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a single file')
    scan_parser.add_argument('file', type=str, help='Path to code file to scan')
    scan_parser.add_argument(
        '--snowflake',
        action='store_true',
        help='Store results in Snowflake'
    )
    scan_parser.add_argument(
        '--no-llm',
        action='store_true',
        help='Disable LLM analysis (faster but less detailed)'
    )
    scan_parser.add_argument(
        '--llm-provider',
        type=str,
        choices=['snowflake_cortex', 'openai', 'anthropic'],
        default='snowflake_cortex',
        help='LLM provider to use (default: snowflake_cortex)'
    )
    scan_parser.add_argument(
        '--format',
        type=str,
        nargs='+',
        choices=['json', 'html', 'markdown'],
        default=['json', 'html'],
        help='Report formats to generate (default: json html)'
    )
    scan_parser.add_argument(
        '--max-size',
        type=int,
        default=10,
        help='Maximum file size in MB (default: 10)'
    )
    scan_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Scan directory command
    scandir_parser = subparsers.add_parser('scan-dir', help='Scan a directory')
    scandir_parser.add_argument('directory', type=str, help='Path to directory to scan')
    scandir_parser.add_argument(
        '--recursive',
        action='store_true',
        help='Scan subdirectories recursively'
    )
    scandir_parser.add_argument(
        '--snowflake',
        action='store_true',
        help='Store results in Snowflake'
    )
    scandir_parser.add_argument(
        '--no-llm',
        action='store_true',
        help='Disable LLM analysis'
    )
    scandir_parser.add_argument(
        '--llm-provider',
        type=str,
        choices=['snowflake_cortex', 'openai', 'anthropic'],
        default='snowflake_cortex',
        help='LLM provider to use'
    )
    scandir_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Web UI command
    ui_parser = subparsers.add_parser('ui', help='Launch web interface')
    ui_parser.add_argument(
        '--port',
        type=int,
        default=8501,
        help='Port to run UI on (default: 8501)'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Handle UI command (main app: Open Nazca Security Analytics)
    if args.command == 'ui':
        try:
            import streamlit.web.cli as stcli
            import sys
            
            app_path = str(Path(__file__).parent / 'app.py')
            sys.argv = ['streamlit', 'run', app_path, '--server.port', str(args.port)]
            sys.exit(stcli.main())
        except ImportError:
            print("❌ Streamlit not installed. Run: pip install streamlit")
            return 1
    
    # Handle scan commands
    setup_logging(args.verbose)
    
    try:
        # Initialize scanner
        scanner = AICodeScanner(
            use_snowflake=args.snowflake,
            use_llm_analysis=(not args.no_llm),
            llm_provider=args.llm_provider if hasattr(args, 'llm_provider') else 'snowflake_cortex',
            max_file_size_mb=args.max_size if hasattr(args, 'max_size') else 10
        )
        
        if args.command == 'scan':
            # Scan single file
            if not Path(args.file).exists():
                print(f"❌ File not found: {args.file}")
                return 1
            
            results = scanner.scan_file(
                file_path=args.file,
                scanned_by="cli_user",
                generate_reports=True,
                report_formats=args.format
            )
            
            if results['success']:
                print(f"\n✅ Scan completed successfully!")
                print(f"   Found {results['total_findings']} vulnerabilities")
                
                if results.get('report_paths'):
                    print(f"\n📄 Reports generated:")
                    for format_type, path in results['report_paths'].items():
                        print(f"   - {format_type.upper()}: {path}")
                
                return 0 if results['total_findings'] == 0 else 1
            else:
                print(f"❌ Scan failed: {results.get('error')}")
                return 1
        
        elif args.command == 'scan-dir':
            # Scan directory
            if not Path(args.directory).exists():
                print(f"❌ Directory not found: {args.directory}")
                return 1
            
            results = scanner.scan_directory(
                directory_path=args.directory,
                recursive=args.recursive,
                scanned_by="cli_user"
            )
            
            total_findings = sum(r.get('total_findings', 0) for r in results if r.get('success'))
            successful_scans = sum(1 for r in results if r.get('success'))
            
            print(f"\n✅ Directory scan completed!")
            print(f"   Scanned {successful_scans}/{len(results)} files")
            print(f"   Found {total_findings} total vulnerabilities")
            
            return 0 if total_findings == 0 else 1
        
        scanner.close()
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

