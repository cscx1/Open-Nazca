"""
Setup script for AI Code Breaker
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="ai-code-breaker",
    version="1.0.0",
    author="Your Hackathon Team",
    author_email="team@example.com",
    description="LLM Security Scanner for AI Systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/LLMCheck",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "snowflake-connector-python>=3.7.0",
        "snowflake-snowpark-python>=1.11.1",
        "openai>=1.12.0",
        "anthropic>=0.18.1",
        "streamlit>=1.31.0",
        "pandas>=2.2.0",
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0.1",
        "requests>=2.31.0",
        "rich>=13.7.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-mock>=3.12.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "llmcheck=cli:main",
        ],
    },
)

