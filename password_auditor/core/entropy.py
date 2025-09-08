"""
Entropy calculation module for password strength analysis.
"""

import math
import re
from typing import Dict, Tuple


class EntropyCalculator:
    """Calculates password entropy and related metrics."""
    
    def __init__(self):
        self.char_sets = {
            'lowercase': set('abcdefghijklmnopqrstuvwxyz'),
            'uppercase': set('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            'digits': set('0123456789'),
            'special': set('!@#$%^&*()_+-=[]{}|;:,.<>?'),
            'space': set(' ')
        }
    
    def calculate_entropy(self, password: str) -> float:
        """
        Calculate Shannon entropy of a password.
        
        Args:
            password: The password to analyze
            
        Returns:
            Entropy value in bits
        """
        if not password:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in password:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        password_length = len(password)
        
        for count in char_counts.values():
            probability = count / password_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def get_character_set_size(self, password: str) -> int:
        """
        Calculate the size of the character set used in the password.
        
        Args:
            password: The password to analyze
            
        Returns:
            Number of unique characters in the password
        """
        return len(set(password))
    
    def analyze_character_sets(self, password: str) -> Dict[str, bool]:
        """
        Analyze which character sets are present in the password.
        
        Args:
            password: The password to analyze
            
        Returns:
            Dictionary indicating which character sets are present
        """
        result = {}
        password_set = set(password)
        
        for set_name, char_set in self.char_sets.items():
            result[set_name] = bool(password_set.intersection(char_set))
        
        return result
    
    def detect_patterns(self, password: str) -> Dict[str, bool]:
        """
        Detect common patterns in passwords.
        
        Args:
            password: The password to analyze
            
        Returns:
            Dictionary of detected patterns
        """
        patterns = {
            'sequential': self._has_sequential_chars(password),
            'repeated': self._has_repeated_chars(password),
            'keyboard_pattern': self._has_keyboard_pattern(password),
            'date_pattern': self._has_date_pattern(password),
            'phone_pattern': self._has_phone_pattern(password)
        }
        
        return patterns
    
    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters (abc, 123, etc.)."""
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and 
                ord(password[i+2]) == ord(password[i]) + 2):
                return True
        return False
    
    def _has_repeated_chars(self, password: str) -> bool:
        """Check for repeated character sequences."""
        for i in range(len(password) - 1):
            if password[i] == password[i+1]:
                return True
        return False
    
    def _has_keyboard_pattern(self, password: str) -> bool:
        """Check for keyboard patterns (qwerty, asdf, etc.)."""
        keyboard_rows = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
            '1234567890'
        ]
        
        password_lower = password.lower()
        for row in keyboard_rows:
            for i in range(len(row) - 2):
                pattern = row[i:i+3]
                if pattern in password_lower:
                    return True
        return False
    
    def _has_date_pattern(self, password: str) -> bool:
        """Check for date patterns (MM/DD/YYYY, etc.)."""
        date_patterns = [
            r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}',  # MM/DD/YYYY
            r'\d{4}[/-]\d{1,2}[/-]\d{1,2}',    # YYYY/MM/DD
            r'\d{6,8}',                         # YYYYMMDD or MMDDYYYY
        ]
        
        for pattern in date_patterns:
            if re.search(pattern, password):
                return True
        return False
    
    def _has_phone_pattern(self, password: str) -> bool:
        """Check for phone number patterns."""
        phone_pattern = r'\d{3}[-.]?\d{3}[-.]?\d{4}'
        return bool(re.search(phone_pattern, password))
    
    def calculate_entropy_score(self, password: str) -> Tuple[float, int]:
        """
        Calculate comprehensive entropy score for a password.
        
        Args:
            password: The password to analyze
            
        Returns:
            Tuple of (entropy_bits, score_0_to_40)
        """
        if not password:
            return 0.0, 0
        
        # Base entropy calculation
        entropy = self.calculate_entropy(password)
        
        # Character set analysis
        char_sets = self.analyze_character_sets(password)
        set_bonus = sum(char_sets.values()) * 2  # 2 points per character set
        
        # Length bonus
        length_bonus = min(len(password) * 0.5, 10)  # Max 10 points for length
        
        # Pattern penalties
        patterns = self.detect_patterns(password)
        pattern_penalty = sum(patterns.values()) * 3  # 3 points penalty per pattern
        
        # Calculate final score (0-40 scale)
        base_score = min(entropy * 2, 20)  # Max 20 points for entropy
        final_score = max(0, base_score + set_bonus + length_bonus - pattern_penalty)
        final_score = min(final_score, 40)  # Cap at 40
        
        return entropy, int(final_score)
