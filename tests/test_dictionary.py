"""
Unit tests for dictionary checking module.
"""

import unittest
import sys
import os

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from password_auditor.core.dictionary import DictionaryChecker


class TestDictionaryChecker(unittest.TestCase):
    """Test cases for DictionaryChecker class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.checker = DictionaryChecker()
    
    def test_check_common_passwords_true(self):
        """Test detection of common passwords."""
        self.assertTrue(self.checker.check_common_passwords("password"))
        self.assertTrue(self.checker.check_common_passwords("123456"))
        self.assertTrue(self.checker.check_common_passwords("qwerty"))
    
    def test_check_common_passwords_false(self):
        """Test non-detection of uncommon passwords."""
        self.assertFalse(self.checker.check_common_passwords("Kj9#mN2$pL8@vR5!"))
        self.assertFalse(self.checker.check_common_passwords("MyUniquePass123"))
    
    def test_check_dictionary_words(self):
        """Test dictionary word detection."""
        words = self.checker.check_dictionary_words("love123")
        self.assertIn("love", words)
        
        words = self.checker.check_dictionary_words("MyStrongPassword")
        self.assertIn("strong", words)
    
    def test_check_leet_speak(self):
        """Test leet speak detection."""
        self.assertTrue(self.checker.check_leet_speak("l0v3"))
        self.assertTrue(self.checker.check_leet_speak("p4ssw0rd"))
    
    def test_check_keyboard_patterns(self):
        """Test keyboard pattern detection."""
        patterns = self.checker.check_keyboard_patterns("qwerty")
        self.assertIn("qwerty", patterns)
        
        patterns = self.checker.check_keyboard_patterns("asdfgh")
        self.assertIn("asdfgh", patterns)
    
    def test_check_sequential_patterns(self):
        """Test sequential pattern detection."""
        patterns = self.checker.check_sequential_patterns("abc123")
        self.assertTrue(len(patterns) > 0)
        
        patterns = self.checker.check_sequential_patterns("123456")
        self.assertTrue(len(patterns) > 0)
    
    def test_check_personal_info_patterns(self):
        """Test personal info pattern detection."""
        patterns = self.checker.check_personal_info_patterns("user2023", "user")
        self.assertIn("contains_username", patterns)
        
        patterns = self.checker.check_personal_info_patterns("password123")
        self.assertTrue(len(patterns) > 0)  # Should detect year pattern
    
    def test_calculate_dictionary_score_weak(self):
        """Test dictionary score for weak password."""
        score, analysis = self.checker.calculate_dictionary_score("password")
        
        self.assertLess(score, 15)  # Should be low score
        self.assertIn("password", analysis['common_passwords'])
    
    def test_calculate_dictionary_score_strong(self):
        """Test dictionary score for strong password."""
        score, analysis = self.checker.calculate_dictionary_score("Kj9#mN2$pL8@vR5!")
        
        self.assertGreater(score, 20)  # Should be higher score
        self.assertEqual(len(analysis['common_passwords']), 0)
    
    def test_calculate_dictionary_score_bounds(self):
        """Test that dictionary score is within bounds."""
        score, analysis = self.checker.calculate_dictionary_score("test")
        
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 30)
    
    def test_calculate_dictionary_score_with_username(self):
        """Test dictionary score calculation with username."""
        score, analysis = self.checker.calculate_dictionary_score("john123", "john")
        
        self.assertLess(score, 30)  # Should be penalized for username
        self.assertIn("contains_username", analysis['personal_info'])


if __name__ == '__main__':
    unittest.main()
