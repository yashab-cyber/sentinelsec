#!/usr/bin/env python3
"""
SentinelSec Setup Script
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = []
req_file = this_directory / "requirements.txt"
if req_file.exists():
    requirements = req_file.read_text().strip().split('\n')
    requirements = [req.strip() for req in requirements if req.strip()]

setup(
    name="sentinelsec",
    version="1.0.0",
    author="Yashab Alam",
    author_email="yashabalam707@gmail.com",
    description="Advanced Intrusion Detection System with AI-based anomaly detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yashab-cyber/sentinelsec",
    project_urls={
        "Bug Reports": "https://github.com/yashab-cyber/sentinelsec/issues",
        "Source": "https://github.com/yashab-cyber/sentinelsec",
        "Documentation": "https://github.com/yashab-cyber/sentinelsec/blob/main/README.md",
        "Funding": "https://github.com/yashab-cyber/sentinelsec/blob/main/DONATE.md",
        "Company": "https://www.zehrasec.com"
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Internet :: Log Analysis",
        "Environment :: Console",
        "Environment :: Win32 (MS Windows)",
        "Environment :: X11 Applications",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
        ],
        "gui": [
            "tkinter",
        ],
    },
    entry_points={
        "console_scripts": [
            "sentinelsec=main:main",
            "sentinelsec-verify=verify_installation:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": [
            "config/*.json",
            "data/*.json",
            "*.md",
            "*.txt",
            "*.bat",
            "*.sh",
            "*.ps1",
        ],
    },
    keywords=[
        "intrusion detection",
        "network security", 
        "cybersecurity",
        "packet analysis",
        "anomaly detection",
        "machine learning",
        "security monitoring",
        "network monitoring",
        "threat detection",
        "vulnerability scanner",
        "cve",
        "ids",
        "security",
    ],
    zip_safe=False,
)
