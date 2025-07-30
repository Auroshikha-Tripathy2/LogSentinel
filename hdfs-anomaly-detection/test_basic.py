#!/usr/bin/env python3
"""
Basic tests for HDFS Anomaly Detection System
"""

import unittest
import json
import os
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

class TestHDFSAnomalyDetection(unittest.TestCase):
    """Basic tests for the HDFS anomaly detection system"""

    def setUp(self):
        """Set up test fixtures"""
        self.project_root = Path(__file__).parent
        self.data_file = self.project_root / "parsed_hdfs_logs.json"
        self.labels_file = self.project_root / "anomaly_label.csv"
        self.detector_file = self.project_root / "enterprise_detector.py"
        self.parser_file = self.project_root / "hdfs_parser.py"

    def test_project_structure(self):
        """Test that essential project files exist"""
        essential_files = [
            "enterprise_detector.py",
            "hdfs_parser.py",
            "verify_labels.py",
            "requirements.txt",
            "README.md",
            "dockerfile",
            "docker-compose.yml",
            "setup.py",
            "Makefile",
            ".gitignore",
            "LICENSE"
        ]
        
        for file_name in essential_files:
            file_path = self.project_root / file_name
            self.assertTrue(file_path.exists(), f"Essential file {file_name} not found")

    def test_data_files_exist(self):
        """Test that data files exist"""
        data_files = [
            "parsed_hdfs_logs.json",
            "anomaly_label.csv",
            "HDFS.log"
        ]
        
        for file_name in data_files:
            file_path = self.project_root / file_name
            self.assertTrue(file_path.exists(), f"Data file {file_name} not found")

    def test_parsed_data_structure(self):
        """Test that parsed data has correct structure"""
        if not self.data_file.exists():
            self.skipTest("Parsed data file not found")
        
        with open(self.data_file, 'r') as f:
            data = json.load(f)
        
        self.assertIsInstance(data, list, "Parsed data should be a list")
        self.assertGreater(len(data), 0, "Parsed data should not be empty")
        
        # Check structure of first item
        if data:
            first_item = data[0]
            required_fields = ['date', 'time', 'line_id', 'level', 'component', 'message', 'block_ids', 'is_anomalous_true']
            
            for field in required_fields:
                self.assertIn(field, first_item, f"Required field {field} missing from parsed data")

    def test_labels_file_exists(self):
        """Test that labels file exists and is readable"""
        self.assertTrue(self.labels_file.exists(), "Anomaly labels file not found")
        
        # Try to read the file
        try:
            with open(self.labels_file, 'r') as f:
                content = f.read()
            self.assertGreater(len(content), 0, "Labels file should not be empty")
        except Exception as e:
            self.fail(f"Could not read labels file: {e}")

    def test_detector_import(self):
        """Test that the detector can be imported"""
        try:
            import enterprise_detector
            self.assertTrue(hasattr(enterprise_detector, 'main'), "Detector should have main function")
        except ImportError as e:
            self.fail(f"Could not import enterprise_detector: {e}")

    def test_parser_import(self):
        """Test that the parser can be imported"""
        try:
            import hdfs_parser
            self.assertTrue(hasattr(hdfs_parser, 'process_structured_hdfs_dataset'), "Parser should have process function")
        except ImportError as e:
            self.fail(f"Could not import hdfs_parser: {e}")

    def test_verify_labels_import(self):
        """Test that verify_labels can be imported"""
        try:
            import verify_labels
            # Basic import test
            self.assertTrue(True, "verify_labels imported successfully")
        except ImportError as e:
            self.fail(f"Could not import verify_labels: {e}")

    def test_requirements_file(self):
        """Test that requirements.txt exists and has content"""
        requirements_file = self.project_root / "requirements.txt"
        self.assertTrue(requirements_file.exists(), "requirements.txt not found")
        
        with open(requirements_file, 'r') as f:
            content = f.read()
        
        self.assertGreater(len(content), 0, "requirements.txt should not be empty")
        
        # Check for essential packages
        essential_packages = ['numpy', 'pandas', 'scikit-learn', 'matplotlib']
        for package in essential_packages:
            self.assertIn(package, content, f"Essential package {package} not found in requirements.txt")

    def test_docker_files(self):
        """Test that Docker files exist and have content"""
        docker_files = ['dockerfile', 'docker-compose.yml']
        
        for file_name in docker_files:
            file_path = self.project_root / file_name
            self.assertTrue(file_path.exists(), f"Docker file {file_name} not found")
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            self.assertGreater(len(content), 0, f"Docker file {file_name} should not be empty")

    def test_readme_content(self):
        """Test that README.md exists and has meaningful content"""
        readme_file = self.project_root / "README.md"
        self.assertTrue(readme_file.exists(), "README.md not found")
        
        with open(readme_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertGreater(len(content), 100, "README.md should have substantial content")
        
        # Check for essential sections
        essential_sections = ['# HDFS Log Anomaly Detection System', '## 🚀 Features', '## 🛠️ Installation']
        for section in essential_sections:
            self.assertIn(section, content, f"Essential section {section} not found in README.md")

    def test_license_file(self):
        """Test that LICENSE file exists and has MIT license content"""
        license_file = self.project_root / "LICENSE"
        self.assertTrue(license_file.exists(), "LICENSE file not found")
        
        with open(license_file, 'r') as f:
            content = f.read()
        
        self.assertIn("MIT License", content, "LICENSE should contain MIT License")
        self.assertIn("Copyright", content, "LICENSE should contain copyright notice")

    def test_setup_py(self):
        """Test that setup.py exists and is valid"""
        setup_file = self.project_root / "setup.py"
        self.assertTrue(setup_file.exists(), "setup.py not found")
        
        with open(setup_file, 'r') as f:
            content = f.read()
        
        self.assertIn("setup(", content, "setup.py should contain setup() call")
        self.assertIn("hdfs-anomaly-detection", content, "setup.py should contain project name")

    def test_makefile(self):
        """Test that Makefile exists and has useful targets"""
        makefile = self.project_root / "Makefile"
        self.assertTrue(makefile.exists(), "Makefile not found")
        
        with open(makefile, 'r') as f:
            content = f.read()
        
        self.assertIn("install:", content, "Makefile should have install target")
        self.assertIn("test:", content, "Makefile should have test target")
        self.assertIn("docker-build:", content, "Makefile should have docker-build target")

    def test_gitignore(self):
        """Test that .gitignore exists and has Python-specific entries"""
        gitignore_file = self.project_root / ".gitignore"
        self.assertTrue(gitignore_file.exists(), ".gitignore not found")
        
        with open(gitignore_file, 'r') as f:
            content = f.read()
        
        self.assertIn("__pycache__", content, ".gitignore should ignore Python cache")
        self.assertIn("*.pyc", content, ".gitignore should ignore Python compiled files")
        self.assertIn("venv", content, ".gitignore should ignore virtual environments")

if __name__ == '__main__':
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestHDFSAnomalyDetection)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Exit with appropriate code
    sys.exit(not result.wasSuccessful()) 