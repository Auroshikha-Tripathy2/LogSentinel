#!/usr/bin/env python3
"""
Setup script for HDFS Anomaly Detection System
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="hdfs-anomaly-detection",
    version="1.0.0",
    author="HDFS Anomaly Detection Team",
    author_email="team@hdfs-anomaly-detection.com",
    description="An enterprise-grade anomaly detection system for HDFS logs",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/hdfs-anomaly-detection",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: System :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "black>=21.0.0",
            "flake8>=3.9.0",
            "sphinx>=4.0.0",
            "sphinx-rtd-theme>=0.5.0",
        ],
        "jupyter": [
            "jupyter>=1.0.0",
            "ipykernel>=6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "hdfs-anomaly-detector=enterprise_detector:main",
            "hdfs-parser=hdfs_parser:main",
            "verify-labels=verify_labels:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.csv", "*.log"],
    },
    zip_safe=False,
    keywords="hdfs, anomaly-detection, machine-learning, cybersecurity, logging",
    project_urls={
        "Bug Reports": "https://github.com/your-username/hdfs-anomaly-detection/issues",
        "Source": "https://github.com/your-username/hdfs-anomaly-detection",
        "Documentation": "https://hdfs-anomaly-detection.readthedocs.io/",
    },
) 