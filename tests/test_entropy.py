"""
Unit tests for entropy calculation module.
"""

import unittest
import sys
import os

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from password_auditor.core.entropy import EntropyCalculator


class TestEntropyCalculator(unittest.TestCase):
    """Test cases for EntropyCalculator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.calculator = EntropyCalculator()
    
    def test_calculate_entropy_empty_password(self):
        """Test entropy calculation for empty password."""
        entropy = self.calculator.calculate_entropy("")
        self.assertEqual(entropy, 0.0)
    
    def test_calculate_entropy_single_character(self):
        """Test entropy calculation for single character."""
        entropy = self.calculator.calculate_entropy("a")
        self.assertEqual(entropy, 0.0)
    
    def test_calculate_entropy_repeated_characters(self):
        """Test entropy calculation for repeated characters."""
        entropy = self.calculator.calculate_entropy("aaaa")
        self.assertEqual(entropy, 0.0)
    
    def test_calculate_entropy_diverse_characters(self):
        """Test entropy calculation for diverse characters."""
        entropy = self.calculator.calculate_entropy("abcd")
        self.assertGreater(entropy, 0.0)
        self.assertEqual(entropy, 2.0)  # log2(4) = 2
    
    def test_get_character_set_size(self):
        """Test character set size calculation."""
        self.assertEqual(self.calculator.get_character_set_size("abc"), 3)
        self.assertEqual(self.calculator.get_character_set_size("aabbcc"), 3)
        self.assertEqual(self.calculator.get_character_set_size(""), 0)
    
    def test_analyze_character_sets(self):
        """Test character set analysis."""
        result = self.calculator.analyze_character_sets("Abc123!")
        
        self.assertTrue(result['lowercase'])
        self.assertTrue(result['uppercase'])
        self.assertTrue(result['digits'])
        self.assertTrue(result['special'])
        self.assertFalse(result['space'])
    
    def test_detect_patterns_sequential(self):
        """Test sequential pattern detection."""
        patterns = self.calculator.detect_patterns("abc123")
        
        self.assertTrue(patterns['sequential'])
        self.assertFalse(patterns['repeated'])
    
    def test_detect_patterns_repeated(self):
        """Test repeated character detection."""
        patterns = self.calculator.detect_patterns("aabbcc")
        
        self.assertTrue(patterns['repeated'])
        self.assertFalse(patterns['sequential'])
    
    def test_detect_patterns_keyboard(self):
        """Test keyboard pattern detection."""
        patterns = self.calculator.detect_patterns("qwerty")
        
        self.assertTrue(patterns['keyboard_pattern'])
    
    def test_detect_patterns_date(self):
        """Test date pattern detection."""
        patterns = self.calculator.detect_patterns("user2023")
        
        self.assertTrue(patterns['date_pattern'])
    
    def test_calculate_entropy_score_weak_password(self):
        """Test entropy score calculation for weak password."""
        entropy, score = self.calculator.calculate_entropy_score("123")
        
        self.assertGreater(entropy, 0)
        self.assertLess(score, 20)  # Should be low score
    
    def test_calculate_entropy_score_strong_password(self):
        """Test entropy score calculation for strong password."""
        entropy, score = self.calculator.calculate_entropy_score("Kj9#mN2$pL8@vR5!")
        
        self.assertGreater(entropy, 0)
        self.assertGreater(score, 20)  # Should be higher score
    
    def test_calculate_entropy_score_bounds(self):
        """Test that entropy score is within bounds."""
        entropy, score = self.calculator.calculate_entropy_score("test")
        
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 40)


if __name__ == '__main__':
    unittest.main()
