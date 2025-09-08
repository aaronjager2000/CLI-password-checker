"""
Password reuse detection module.
"""

import hashlib
from typing import Dict, List, Set, Tuple
from collections import defaultdict


class ReuseDetector:
    """Detects password reuse and similarity patterns using efficient hash-based detection."""
    
    def __init__(self):
        self.password_hashes = {}  # hash -> {username, password, hash}
        self.user_passwords = defaultdict(list)  # username -> [passwords]
        self.hash_set = set()  # Set of all password hashes for O(1) lookup
        self.similarity_threshold = 0.8  # 80% similarity threshold
    
    def add_password(self, username: str, password: str) -> None:
        """
        Add a password to the analysis pool.
        
        Args:
            username: The username associated with the password
            password: The password to add
        """
        password_hash = self._hash_password(password)
        
        # Store password data
        self.password_hashes[password_hash] = {
            'username': username,
            'password': password,
            'hash': password_hash
        }
        self.user_passwords[username].append(password)
        
        # Add hash to set for O(1) lookup
        self.hash_set.add(password_hash)
    
    def _hash_password(self, password: str) -> str:
        """
        Create a hash of the password for comparison.
        
        Args:
            password: The password to hash
            
        Returns:
            SHA-256 hash of the password
        """
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def detect_exact_duplicates(self) -> Dict[str, List[Dict]]:
        """
        Detect exactly duplicate passwords using efficient hash-based detection.
        
        Returns:
            Dictionary mapping password hashes to lists of users
        """
        hash_to_users = defaultdict(list)
        
        # O(M) - iterate through all stored passwords
        for password_hash, data in self.password_hashes.items():
            hash_to_users[password_hash].append({
                'username': data['username'],
                'password': data['password']
            })
        
        # Filter out single-use passwords (duplicates only)
        return {hash_val: users for hash_val, users in hash_to_users.items() 
                if len(users) > 1}
    
    def is_password_reused(self, password: str) -> Tuple[bool, int]:
        """
        Efficiently check if a password is reused using hash-based detection.
        
        Args:
            password: The password to check
            
        Returns:
            Tuple of (is_reused, duplicate_count)
        """
        password_hash = self._hash_password(password)
        
        # O(1) lookup in hash set
        if password_hash in self.hash_set:
            # Count how many times this password appears
            duplicate_count = len(self.password_hashes[password_hash])
            return True, duplicate_count
        
        return False, 0
    
    def detect_user_reuse(self) -> Dict[str, List[str]]:
        """
        Detect password reuse within individual users.
        
        Returns:
            Dictionary mapping usernames to lists of duplicate passwords
        """
        user_reuse = {}
        
        for username, passwords in self.user_passwords.items():
            if len(passwords) > 1:
                # Check for duplicates within user's passwords
                unique_passwords = set(passwords)
                if len(unique_passwords) < len(passwords):
                    duplicates = [pwd for pwd in passwords 
                                if passwords.count(pwd) > 1]
                    user_reuse[username] = list(set(duplicates))
        
        return user_reuse
    
    def calculate_similarity(self, password1: str, password2: str) -> float:
        """
        Calculate similarity between two passwords using Jaccard similarity.
        
        Args:
            password1: First password
            password2: Second password
            
        Returns:
            Similarity score between 0 and 1
        """
        if not password1 or not password2:
            return 0.0
        
        # Convert to character sets
        set1 = set(password1.lower())
        set2 = set(password2.lower())
        
        # Calculate Jaccard similarity
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        if union == 0:
            return 0.0
        
        return intersection / union
    
    def detect_similar_passwords(self) -> List[Dict]:
        """
        Detect similar passwords across all users.
        
        Returns:
            List of similar password groups
        """
        similar_groups = []
        processed_hashes = set()
        
        password_list = list(self.password_hashes.values())
        
        for i, password_data1 in enumerate(password_list):
            if password_data1['hash'] in processed_hashes:
                continue
            
            similar_group = [password_data1]
            processed_hashes.add(password_data1['hash'])
            
            for j, password_data2 in enumerate(password_list[i+1:], i+1):
                if password_data2['hash'] in processed_hashes:
                    continue
                
                similarity = self.calculate_similarity(
                    password_data1['password'],
                    password_data2['password']
                )
                
                if similarity >= self.similarity_threshold:
                    similar_group.append(password_data2)
                    processed_hashes.add(password_data2['hash'])
            
            if len(similar_group) > 1:
                similar_groups.append(similar_group)
        
        return similar_groups
    
    def detect_common_patterns(self) -> Dict[str, List[Dict]]:
        """
        Detect common password patterns across users.
        
        Returns:
            Dictionary of pattern types to matching passwords
        """
        patterns = {
            'sequential_numbers': [],
            'common_suffixes': [],
            'common_prefixes': [],
            'year_patterns': [],
            'name_patterns': []
        }
        
        import re
        
        for password_data in self.password_hashes.values():
            password = password_data['password']
            
            # Sequential numbers (123, 456, etc.)
            if re.search(r'\d{3,}', password):
                if self._is_sequential(password):
                    patterns['sequential_numbers'].append(password_data)
            
            # Common suffixes
            common_suffixes = ['123', '456', '789', '000', '111', '999']
            for suffix in common_suffixes:
                if password.endswith(suffix):
                    patterns['common_suffixes'].append(password_data)
                    break
            
            # Common prefixes
            common_prefixes = ['abc', 'qwe', 'asd', 'zxc']
            for prefix in common_prefixes:
                if password.lower().startswith(prefix):
                    patterns['common_prefixes'].append(password_data)
                    break
            
            # Year patterns
            if re.search(r'(19|20)\d{2}', password):
                patterns['year_patterns'].append(password_data)
        
        # Filter out patterns with only one occurrence
        return {pattern: passwords for pattern, passwords in patterns.items() 
                if len(passwords) > 1}
    
    def _is_sequential(self, password: str) -> bool:
        """Check if password contains sequential numbers."""
        import re
        numbers = re.findall(r'\d+', password)
        for num_str in numbers:
            if len(num_str) >= 3:
                for i in range(len(num_str) - 2):
                    if (int(num_str[i+1]) == int(num_str[i]) + 1 and
                        int(num_str[i+2]) == int(num_str[i]) + 2):
                        return True
        return False
    
    def calculate_reuse_score(self, username: str, password: str) -> Tuple[int, Dict]:
        """
        Calculate reuse-based security score for a specific password using efficient hash-based detection.
        
        Args:
            username: The username associated with the password
            password: The password to analyze
            
        Returns:
            Tuple of (score_0_to_30, analysis_details)
        """
        score = 30  # Start with full points
        analysis = {
            'exact_duplicates': 0,
            'user_reuse': False,
            'similar_passwords': 0,
            'common_patterns': []
        }
        
        # O(1) check for exact duplicates using hash-based detection
        is_reused, duplicate_count = self.is_password_reused(password)
        if is_reused:
            score -= min(duplicate_count * 5, 15)  # Max 15 point penalty
            analysis['exact_duplicates'] = duplicate_count
        
        # Check for user-specific reuse (O(1) for single user)
        if username in self.user_passwords:
            user_passwords = self.user_passwords[username]
            if user_passwords.count(password) > 1:
                score -= 10
                analysis['user_reuse'] = True
        
        # Skip expensive similar password detection for performance
        # This could be optimized further with more sophisticated algorithms
        # but for now we'll focus on exact duplicates which are the main concern
        
        return max(0, score), analysis
    
    def get_reuse_statistics(self) -> Dict:
        """
        Get overall reuse statistics using efficient hash-based detection.
        
        Returns:
            Dictionary of reuse statistics
        """
        # Use efficient methods only
        exact_duplicates = self.detect_exact_duplicates()
        user_reuse = self.detect_user_reuse()
        common_patterns = self.detect_common_patterns()
        
        total_passwords = len(self.password_hashes)
        duplicate_passwords = sum(len(users) for users in exact_duplicates.values())
        users_with_reuse = len(user_reuse)
        
        # Skip expensive similar password detection for performance
        # This would require O(n²) comparisons which is too slow for large datasets
        similar_groups = 0  # Placeholder - could be calculated separately if needed
        
        return {
            'total_passwords': total_passwords,
            'unique_passwords': total_passwords - duplicate_passwords + len(exact_duplicates),
            'duplicate_passwords': duplicate_passwords,
            'users_with_reuse': users_with_reuse,
            'similar_groups': similar_groups,
            'common_patterns': {pattern: len(passwords) for pattern, passwords in common_patterns.items()}
        }
