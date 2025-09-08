"""
Hashing utilities for password analysis.
"""

import hashlib
from typing import Dict, List


class HashingUtils:
    """Utility class for password hashing operations."""
    
    @staticmethod
    def sha256_hash(password: str) -> str:
        """
        Create SHA-256 hash of a password.
        
        Args:
            password: The password to hash
            
        Returns:
            SHA-256 hash as hexadecimal string
        """
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    @staticmethod
    def md5_hash(password: str) -> str:
        """
        Create MD5 hash of a password.
        
        Args:
            password: The password to hash
            
        Returns:
            MD5 hash as hexadecimal string
        """
        return hashlib.md5(password.encode('utf-8')).hexdigest()
    
    @staticmethod
    def sha1_hash(password: str) -> str:
        """
        Create SHA-1 hash of a password.
        
        Args:
            password: The password to hash
            
        Returns:
            SHA-1 hash as hexadecimal string
        """
        return hashlib.sha1(password.encode('utf-8')).hexdigest()
    
    @staticmethod
    def create_password_fingerprint(password: str) -> Dict[str, str]:
        """
        Create multiple hash fingerprints for a password.
        
        Args:
            password: The password to fingerprint
            
        Returns:
            Dictionary of hash types and their values
        """
        return {
            'sha256': HashingUtils.sha256_hash(password),
            'md5': HashingUtils.md5_hash(password),
            'sha1': HashingUtils.sha1_hash(password)
        }
    
    @staticmethod
    def find_hash_collisions(passwords: List[str], hash_type: str = 'sha256') -> Dict[str, List[str]]:
        """
        Find passwords that produce the same hash.
        
        Args:
            passwords: List of passwords to check
            hash_type: Type of hash to use ('sha256', 'md5', 'sha1')
            
        Returns:
            Dictionary mapping hashes to lists of passwords that produce them
        """
        hash_to_passwords = {}
        
        for password in passwords:
            if hash_type == 'sha256':
                hash_value = HashingUtils.sha256_hash(password)
            elif hash_type == 'md5':
                hash_value = HashingUtils.md5_hash(password)
            elif hash_type == 'sha1':
                hash_value = HashingUtils.sha1_hash(password)
            else:
                raise ValueError(f"Unsupported hash type: {hash_type}")
            
            if hash_value not in hash_to_passwords:
                hash_to_passwords[hash_value] = []
            hash_to_passwords[hash_value].append(password)
        
        # Filter out single passwords (no collisions)
        return {hash_val: passwords for hash_val, passwords in hash_to_passwords.items() 
                if len(passwords) > 1}
