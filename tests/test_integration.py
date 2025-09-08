"""
Integration tests for the password auditor.
"""

import unittest
import sys
import os
import tempfile
import csv

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from password_auditor.core.analyzer import PasswordAnalyzer
from password_auditor.utils.csv_handler import CSVHandler
from password_auditor.utils.validators import InputValidator


class TestPasswordAuditorIntegration(unittest.TestCase):
    """Integration tests for the password auditor system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = PasswordAnalyzer()
        self.csv_handler = CSVHandler()
        
        # Create test data
        self.test_data = [
            ("user1", "password123"),
            ("user2", "qwerty"),
            ("user3", "Kj9#mN2$pL8@vR5!"),
            ("user4", "123456"),
            ("user5", "MyStrongPass2023!")
        ]
    
    def test_analyzer_integration(self):
        """Test the main analyzer integration."""
        results = self.analyzer.analyze_passwords(self.test_data)
        
        # Should have 5 results
        self.assertEqual(len(results), 5)
        
        # Results should be sorted by score (weakest first)
        scores = [r['total_score'] for r in results]
        self.assertEqual(scores, sorted(scores))
        
        # Check that all required fields are present
        for result in results:
            self.assertIn('username', result)
            self.assertIn('password', result)
            self.assertIn('total_score', result)
            self.assertIn('strength_category', result)
            self.assertIn('scores', result)
            self.assertIn('entropy', result)
            self.assertIn('dictionary', result)
            self.assertIn('reuse', result)
    
    def test_csv_handler_integration(self):
        """Test CSV handler integration."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            writer = csv.writer(f)
            writer.writerow(['username', 'password'])
            for username, password in self.test_data:
                writer.writerow([username, password])
            temp_file = f.name
        
        try:
            # Test reading
            loaded_data = self.csv_handler.read_password_csv(temp_file)
            self.assertEqual(len(loaded_data), 5)
            self.assertEqual(loaded_data[0], ("user1", "password123"))
            
            # Test validation
            is_valid, errors = self.csv_handler.validate_csv_format(temp_file)
            self.assertTrue(is_valid)
            self.assertEqual(len(errors), 0)
            
        finally:
            os.unlink(temp_file)
    
    def test_full_workflow(self):
        """Test the complete workflow from CSV to analysis."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            writer = csv.writer(f)
            writer.writerow(['username', 'password'])
            for username, password in self.test_data:
                writer.writerow([username, password])
            temp_file = f.name
        
        try:
            # Load data
            password_data = self.csv_handler.read_password_csv(temp_file)
            
            # Analyze
            results = self.analyzer.analyze_passwords(password_data)
            
            # Get statistics
            stats = self.analyzer.get_summary_statistics()
            
            # Verify results
            self.assertEqual(len(results), 5)
            self.assertEqual(stats['total_passwords'], 5)
            self.assertGreater(stats['average_score'], 0)
            self.assertLessEqual(stats['average_score'], 100)
            
            # Test filtering
            weak_passwords = self.analyzer.get_top_weak_passwords(2)
            self.assertEqual(len(weak_passwords), 2)
            
            strong_passwords = self.analyzer.get_top_strong_passwords(2)
            self.assertEqual(len(strong_passwords), 2)
            
        finally:
            os.unlink(temp_file)
    
    def test_export_functionality(self):
        """Test export functionality."""
        results = self.analyzer.analyze_passwords(self.test_data)
        
        # Test JSON export
        json_export = self.analyzer.export_results('json')
        self.assertIsInstance(json_export, str)
        self.assertIn('username', json_export)
        
        # Test CSV export
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            temp_file = f.name
        
        try:
            self.csv_handler.write_results_csv(results, temp_file)
            
            # Verify CSV was created and has content
            self.assertTrue(os.path.exists(temp_file))
            with open(temp_file, 'r') as f:
                content = f.read()
                self.assertIn('username', content)
                self.assertIn('password', content)
                self.assertIn('total_score', content)
                
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_input_validation(self):
        """Test input validation integration."""
        # Test valid data
        is_valid, errors = InputValidator.validate_password_data(self.test_data)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
        
        # Test invalid data
        invalid_data = [
            ("", "password"),  # Empty username
            ("user", ""),      # Empty password
            ("user1", "password"),  # Duplicate username
        ]
        
        is_valid, errors = InputValidator.validate_password_data(invalid_data)
        self.assertFalse(is_valid)
        self.assertGreater(len(errors), 0)
    
    def test_reuse_detection_integration(self):
        """Test password reuse detection integration."""
        # Add duplicate passwords
        test_data_with_duplicates = self.test_data + [
            ("user6", "password123"),  # Duplicate of user1
            ("user7", "qwerty"),       # Duplicate of user2
        ]
        
        results = self.analyzer.analyze_passwords(test_data_with_duplicates)
        
        # Check that reuse was detected
        reuse_stats = self.analyzer.get_summary_statistics()['reuse_statistics']
        self.assertGreater(reuse_stats['duplicate_passwords'], 0)
        
        # Find the duplicate passwords in results
        duplicate_results = [r for r in results if r['reuse']['exact_duplicates'] > 0]
        self.assertGreater(len(duplicate_results), 0)


if __name__ == '__main__':
    unittest.main()
