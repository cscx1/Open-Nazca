"""
Code Ingestion Module for AI Code Breaker
Safely reads and processes code files for security scanning.
"""

import os
import hashlib
from pathlib import Path
from typing import Dict, Optional, List
import logging

logger = logging.getLogger(__name__)


class CodeIngestion:
    """
    Handles safe ingestion of code files for security analysis.
    Supports Python, JavaScript, TypeScript, and other languages.
    """
    
    # Supported file extensions and their language mappings
    LANGUAGE_EXTENSIONS = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.go': 'go',
        '.rs': 'rust',
        '.rb': 'ruby',
        '.php': 'php',
        '.swift': 'swift',
        '.kt': 'kotlin',
    }
    
    def __init__(self, max_file_size_mb: int = 10):
        """
        Initialize code ingestion handler.
        
        Args:
            max_file_size_mb: Maximum file size to process (default 10MB)
        """
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        logger.info(f"Code ingestion initialized (max file size: {max_file_size_mb}MB)")
    
    def detect_language(self, file_path: str) -> Optional[str]:
        """
        Detect programming language from file extension.
        
        Args:
            file_path: Path to the code file
        
        Returns:
            Language name or None if unsupported
        """
        extension = Path(file_path).suffix.lower()
        return self.LANGUAGE_EXTENSIONS.get(extension)
    
    def validate_file(self, file_path: str) -> Dict[str, any]:
        """
        Validate that a file can be safely processed.
        
        Args:
            file_path: Path to the file to validate
        
        Returns:
            Dictionary with validation results and metadata
        
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file is invalid for processing
        """
        path = Path(file_path)
        
        # Check if file exists
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Check if it's a file (not a directory)
        if not path.is_file():
            raise ValueError(f"Not a file: {file_path}")
        
        # Get file size
        file_size = path.stat().st_size
        
        # Check file size limit
        if file_size > self.max_file_size_bytes:
            raise ValueError(
                f"File too large: {file_size / (1024*1024):.2f}MB "
                f"(max: {self.max_file_size_bytes / (1024*1024)}MB)"
            )
        
        # Check if file is empty
        if file_size == 0:
            raise ValueError("File is empty")
        
        # Detect language
        language = self.detect_language(file_path)
        if not language:
            raise ValueError(
                f"Unsupported file type: {path.suffix}. "
                f"Supported: {', '.join(self.LANGUAGE_EXTENSIONS.keys())}"
            )
        
        return {
            'valid': True,
            'file_path': str(path.absolute()),
            'file_name': path.name,
            'file_size': file_size,
            'language': language,
            'extension': path.suffix
        }
    
    def read_file_safe(self, file_path: str) -> str:
        """
        Safely read file contents with proper encoding handling.
        
        Args:
            file_path: Path to the file to read
        
        Returns:
            File contents as string
        
        Raises:
            UnicodeDecodeError: If file cannot be decoded as text
        """
        try:
            # Try UTF-8 first (most common)
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Fallback to latin-1 if UTF-8 fails
            logger.warning(f"UTF-8 decode failed for {file_path}, trying latin-1")
            with open(file_path, 'r', encoding='latin-1') as f:
                return f.read()
    
    def compute_file_hash(self, content: str) -> str:
        """
        Compute SHA-256 hash of file content for deduplication.
        
        Args:
            content: File content as string
        
        Returns:
            Hexadecimal hash string
        """
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def ingest_file(self, file_path: str) -> Dict[str, any]:
        """
        Complete ingestion pipeline for a single code file.
        
        Args:
            file_path: Path to the code file
        
        Returns:
            Dictionary containing file metadata and content
        """
        try:
            # Validate file
            validation = self.validate_file(file_path)
            logger.info(f"✓ Validated: {validation['file_name']} ({validation['language']})")
            
            # Read file content
            content = self.read_file_safe(file_path)
            logger.info(f"✓ Read: {len(content)} characters")
            
            # Compute hash for deduplication
            file_hash = self.compute_file_hash(content)
            
            # Count lines
            line_count = content.count('\n') + 1
            
            # Build complete file metadata
            file_data = {
                'file_name': validation['file_name'],
                'file_path': validation['file_path'],
                'language': validation['language'],
                'file_size_bytes': validation['file_size'],
                'code_content': content,
                'file_hash': file_hash,
                'line_count': line_count,
                'metadata': {
                    'extension': validation['extension'],
                    'encoding': 'utf-8'
                }
            }
            
            logger.info(
                f"✓ Ingested: {file_data['file_name']} "
                f"({file_data['line_count']} lines, {file_data['language']})"
            )
            
            return file_data
            
        except Exception as e:
            logger.error(f"✗ Failed to ingest {file_path}: {e}")
            raise
    
    def ingest_directory(
        self,
        directory_path: str,
        recursive: bool = True,
        exclude_patterns: Optional[List[str]] = None
    ) -> List[Dict[str, any]]:
        """
        Ingest all supported code files from a directory.
        
        Args:
            directory_path: Path to directory to scan
            recursive: Whether to scan subdirectories
            exclude_patterns: List of patterns to exclude (e.g., ['test_', '__pycache__'])
        
        Returns:
            List of ingested file data dictionaries
        """
        if exclude_patterns is None:
            exclude_patterns = ['__pycache__', '.git', 'node_modules', 'venv', '.env']
        
        ingested_files = []
        path = Path(directory_path)
        
        if not path.exists() or not path.is_dir():
            raise ValueError(f"Invalid directory: {directory_path}")
        
        # Determine search pattern
        pattern = '**/*' if recursive else '*'
        
        # Find all files with supported extensions
        for ext in self.LANGUAGE_EXTENSIONS.keys():
            for file_path in path.glob(f"{pattern}{ext}"):
                # Check if file should be excluded
                should_exclude = any(
                    pattern in str(file_path)
                    for pattern in exclude_patterns
                )
                
                if should_exclude:
                    logger.debug(f"Skipping excluded file: {file_path}")
                    continue
                
                try:
                    file_data = self.ingest_file(str(file_path))
                    ingested_files.append(file_data)
                except Exception as e:
                    logger.warning(f"Skipping {file_path}: {e}")
                    continue
        
        logger.info(f"✓ Ingested {len(ingested_files)} files from {directory_path}")
        return ingested_files
    
    def ingest_and_store(
        self,
        file_path: str,
        snowflake_client,
        scanned_by: str = "system"
    ) -> str:
        """
        Ingest a file and immediately store it in Snowflake.
        
        Args:
            file_path: Path to the code file
            snowflake_client: SnowflakeClient instance
            scanned_by: User or system initiating the scan
        
        Returns:
            scan_id: UUID of the created scan record
        """
        # Ingest the file
        file_data = self.ingest_file(file_path)
        
        # Store in Snowflake
        scan_id = snowflake_client.insert_code_scan(
            file_name=file_data['file_name'],
            file_path=file_data['file_path'],
            language=file_data['language'],
            code_content=file_data['code_content'],
            file_size_bytes=file_data['file_size_bytes'],
            scanned_by=scanned_by,
            metadata=file_data['metadata']
        )
        
        logger.info(f"✓ Stored in Snowflake with scan_id: {scan_id}")
        return scan_id


# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create ingestion handler
    ingestion = CodeIngestion(max_file_size_mb=10)
    
    # Example: Ingest a single file
    # file_data = ingestion.ingest_file("example.py")
    # print(f"Ingested: {file_data['file_name']}")
    
    print("Code ingestion module ready!")

