"""
Dictionary-based password analysis module.
"""

import re
from typing import List, Dict, Set, Tuple
from pathlib import Path


class DictionaryChecker:
    """Checks passwords against common dictionaries and patterns."""
    
    def __init__(self, dictionary_file: str = None):
        """
        Initialize the dictionary checker.
        
        Args:
            dictionary_file: Path to dictionary file (optional)
        """
        self.common_passwords = self._load_common_passwords(dictionary_file)
        self.common_words = self._load_common_words()
        self.leet_speak_map = self._create_leet_speak_map()
    
    def _load_common_passwords(self, dictionary_file: str = None) -> Set[str]:
        """Load common passwords from file or use built-in list."""
        if dictionary_file and Path(dictionary_file).exists():
            with open(dictionary_file, 'r', encoding='utf-8') as f:
                return {line.strip().lower() for line in f if line.strip()}
        
        # Built-in common passwords
        return {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'password1', 'qwerty123', 'dragon', 'master',
            'hello', 'freedom', 'whatever', 'qazwsx', 'trustno1',
            '654321', 'jordan23', 'harley', 'password1', 'shadow',
            'superman', 'qazwsx', 'michael', 'football', 'jordan',
            'hunter', 'ranger', 'daniel', 'hannah', 'maggie',
            'jessica', 'charlie', 'michelle', 'andrew', 'joshua',
            'jennifer', 'amanda', 'jessica', 'samantha', 'ashley',
            'matthew', 'christopher', 'anthony', 'joshua', 'andrew',
            'daniel', 'david', 'william', 'james', 'robert',
            'john', 'michael', 'christopher', 'daniel', 'matthew'
        }
    
    def _load_common_words(self) -> Set[str]:
        """Load common English words."""
        # Common English words that are often used in passwords
        return {
            'love', 'life', 'happy', 'dream', 'hope', 'peace', 'faith',
            'angel', 'heart', 'soul', 'spirit', 'magic', 'power',
            'strong', 'brave', 'courage', 'wisdom', 'truth', 'beauty',
            'freedom', 'justice', 'honor', 'loyalty', 'family', 'friend',
            'home', 'house', 'car', 'money', 'work', 'time', 'day',
            'night', 'sun', 'moon', 'star', 'sky', 'sea', 'mountain',
            'river', 'tree', 'flower', 'bird', 'cat', 'dog', 'horse',
            'lion', 'tiger', 'bear', 'wolf', 'eagle', 'fish', 'snake'
        }
    
    def _create_leet_speak_map(self) -> Dict[str, str]:
        """Create leet speak character mapping."""
        return {
            'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5',
            't': '7', 'l': '1', 'g': '9', 'b': '6', 'z': '2'
        }
    
    def check_common_passwords(self, password: str) -> bool:
        """
        Check if password is in common password list.
        
        Args:
            password: The password to check
            
        Returns:
            True if password is common
        """
        return password.lower() in self.common_passwords
    
    def check_dictionary_words(self, password: str) -> List[str]:
        """
        Check if password contains dictionary words.
        
        Args:
            password: The password to check
            
        Returns:
            List of found dictionary words
        """
        found_words = []
        password_lower = password.lower()
        
        for word in self.common_words:
            if word in password_lower:
                found_words.append(word)
        
        return found_words
    
    def check_leet_speak(self, password: str) -> bool:
        """
        Check if password uses leet speak substitutions.
        
        Args:
            password: The password to check
            
        Returns:
            True if leet speak is detected
        """
        # Convert leet speak back to normal characters
        normal_password = password.lower()
        for leet_char, normal_char in self.leet_speak_map.items():
            normal_password = normal_password.replace(leet_char, normal_char)
        
        # Check if the normalized version is a common word
        return normal_password in self.common_words or normal_password in self.common_passwords
    
    def check_keyboard_patterns(self, password: str) -> List[str]:
        """
        Check for keyboard patterns in password.
        
        Args:
            password: The password to check
            
        Returns:
            List of detected keyboard patterns
        """
        patterns = []
        password_lower = password.lower()
        
        # Common keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop', 'asdfghjkl',
            'zxcvbnm', '123456', '654321', 'qazwsx', 'wsxedc',
            'rfvtgb', 'yhnujm', 'qwertyuiopasdfghjklzxcvbnm'
        ]
        
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                patterns.append(pattern)
        
        return patterns
    
    def check_sequential_patterns(self, password: str) -> List[str]:
        """
        Check for sequential character patterns.
        
        Args:
            password: The password to check
            
        Returns:
            List of detected sequential patterns
        """
        patterns = []
        
        # Check for sequential numbers
        for i in range(len(password) - 2):
            if (password[i:i+3].isdigit() and 
                ord(password[i+1]) == ord(password[i]) + 1 and
                ord(password[i+2]) == ord(password[i]) + 2):
                patterns.append(password[i:i+3])
        
        # Check for sequential letters
        for i in range(len(password) - 2):
            if (password[i:i+3].isalpha() and 
                ord(password[i+1].lower()) == ord(password[i].lower()) + 1 and
                ord(password[i+2].lower()) == ord(password[i].lower()) + 2):
                patterns.append(password[i:i+3])
        
        return patterns
    
    def check_personal_info_patterns(self, password: str, username: str = None) -> List[str]:
        """
        Check for personal information patterns.
        
        Args:
            password: The password to check
            username: Associated username (optional)
            
        Returns:
            List of detected personal info patterns
        """
        patterns = []
        password_lower = password.lower()
        
        if username:
            username_lower = username.lower()
            # Check if username is in password
            if username_lower in password_lower:
                patterns.append(f"contains_username")
            
            # Check for reversed username
            if username_lower[::-1] in password_lower:
                patterns.append(f"contains_reversed_username")
        
        # Check for common personal info patterns
        personal_patterns = [
            r'\b(19|20)\d{2}\b',  # Years
            r'\b(0[1-9]|1[0-2])[\/\-](0[1-9]|[12][0-9]|3[01])[\/\-](19|20)\d{2}\b',  # Dates
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone numbers
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email patterns
        ]
        
        for pattern in personal_patterns:
            if re.search(pattern, password):
                patterns.append(f"personal_info_pattern")
        
        return patterns
    
    def calculate_dictionary_score(self, password: str, username: str = None) -> Tuple[int, Dict[str, List[str]]]:
        """
        Calculate dictionary-based security score.
        
        Args:
            password: The password to analyze
            username: Associated username (optional)
            
        Returns:
            Tuple of (score_0_to_30, analysis_details)
        """
        score = 30  # Start with full points
        analysis = {
            'common_passwords': [],
            'dictionary_words': [],
            'leet_speak': False,
            'keyboard_patterns': [],
            'sequential_patterns': [],
            'personal_info': []
        }
        
        # Check common passwords (major penalty)
        if self.check_common_passwords(password):
            score -= 20
            analysis['common_passwords'].append(password)
        
        # Check dictionary words
        dict_words = self.check_dictionary_words(password)
        if dict_words:
            score -= len(dict_words) * 3
            analysis['dictionary_words'] = dict_words
        
        # Check leet speak
        if self.check_leet_speak(password):
            score -= 5
            analysis['leet_speak'] = True
        
        # Check keyboard patterns
        keyboard_patterns = self.check_keyboard_patterns(password)
        if keyboard_patterns:
            score -= len(keyboard_patterns) * 4
            analysis['keyboard_patterns'] = keyboard_patterns
        
        # Check sequential patterns
        sequential_patterns = self.check_sequential_patterns(password)
        if sequential_patterns:
            score -= len(sequential_patterns) * 3
            analysis['sequential_patterns'] = sequential_patterns
        
        # Check personal info
        personal_patterns = self.check_personal_info_patterns(password, username)
        if personal_patterns:
            score -= len(personal_patterns) * 2
            analysis['personal_info'] = personal_patterns
        
        return max(0, score), analysis
