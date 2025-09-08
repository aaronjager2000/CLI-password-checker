"""
Input validation utilities.
"""

import re
from typing import List, Tuple, Optional
from pathlib import Path


class InputValidator:
    """Validates various types of input for the password auditor."""
    
    @staticmethod
    def validate_file_path(file_path: str, required_extensions: List[str] = None) -> Tuple[bool, str]:
        """
        Validate file path.
        
        Args:
            file_path: Path to validate
            required_extensions: List of required file extensions
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not file_path:
            return False, "File path cannot be empty"
        
        path = Path(file_path)
        
        if not path.exists():
            return False, f"File does not exist: {file_path}"
        
        if not path.is_file():
            return False, f"Path is not a file: {file_path}"
        
        if required_extensions:
            if path.suffix.lower() not in [ext.lower() for ext in required_extensions]:
                return False, f"File must have one of these extensions: {', '.join(required_extensions)}"
        
        return True, ""
    
    @staticmethod
    def validate_output_path(output_path: str, create_dirs: bool = True) -> Tuple[bool, str]:
        """
        Validate output path and create directories if needed.
        
        Args:
            output_path: Output path to validate
            create_dirs: Whether to create parent directories
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not output_path:
            return False, "Output path cannot be empty"
        
        path = Path(output_path)
        
        # Check if parent directory exists or can be created
        parent_dir = path.parent
        if not parent_dir.exists():
            if create_dirs:
                try:
                    parent_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    return False, f"Cannot create output directory: {str(e)}"
            else:
                return False, f"Output directory does not exist: {parent_dir}"
        
        # Check if we can write to the directory
        if not parent_dir.is_dir():
            return False, f"Output path parent is not a directory: {parent_dir}"
        
        return True, ""
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """
        Validate username format.
        
        Args:
            username: Username to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not username:
            return False, "Username cannot be empty"
        
        if len(username) < 1:
            return False, "Username must be at least 1 character long"
        
        if len(username) > 100:
            return False, "Username cannot be longer than 100 characters"
        
        # Check for invalid characters
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            return False, "Username can only contain letters, numbers, dots, underscores, and hyphens"
        
        return True, ""
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """
        Validate password format.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not password:
            return False, "Password cannot be empty"
        
        if len(password) < 1:
            return False, "Password must be at least 1 character long"
        
        if len(password) > 1000:
            return False, "Password cannot be longer than 1000 characters"
        
        return True, ""
    
    @staticmethod
    def validate_score_threshold(threshold: int) -> Tuple[bool, str]:
        """
        Validate score threshold.
        
        Args:
            threshold: Score threshold to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(threshold, int):
            return False, "Score threshold must be an integer"
        
        if threshold < 0 or threshold > 100:
            return False, "Score threshold must be between 0 and 100"
        
        return True, ""
    
    @staticmethod
    def validate_limit(limit: int) -> Tuple[bool, str]:
        """
        Validate limit parameter.
        
        Args:
            limit: Limit to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(limit, int):
            return False, "Limit must be an integer"
        
        if limit < 1:
            return False, "Limit must be at least 1"
        
        if limit > 10000:
            return False, "Limit cannot exceed 10000"
        
        return True, ""
    
    @staticmethod
    def validate_export_format(format_str: str) -> Tuple[bool, str]:
        """
        Validate export format.
        
        Args:
            format_str: Export format to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        valid_formats = ['json', 'csv', 'txt']
        
        if not format_str:
            return False, "Export format cannot be empty"
        
        if format_str.lower() not in valid_formats:
            return False, f"Export format must be one of: {', '.join(valid_formats)}"
        
        return True, ""
    
    @staticmethod
    def validate_password_data(password_data: List[Tuple[str, str]]) -> Tuple[bool, List[str]]:
        """
        Validate a list of password data.
        
        Args:
            password_data: List of (username, password) tuples
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        if not password_data:
            errors.append("No password data provided")
            return False, errors
        
        if len(password_data) > 10000:
            errors.append("Too many passwords (maximum 10000 allowed)")
        
        usernames = set()
        passwords = set()
        
        for i, (username, password) in enumerate(password_data):
            # Validate username
            is_valid, error = InputValidator.validate_username(username)
            if not is_valid:
                errors.append(f"Row {i+1}: {error}")
            
            # Validate password
            is_valid, error = InputValidator.validate_password(password)
            if not is_valid:
                errors.append(f"Row {i+1}: {error}")
            
            # Check for duplicate usernames
            if username in usernames:
                errors.append(f"Row {i+1}: Duplicate username '{username}'")
            usernames.add(username)
            
            # Check for duplicate passwords (warning, not error)
            if password in passwords:
                errors.append(f"Row {i+1}: Duplicate password detected")
            passwords.add(password)
        
        return len(errors) == 0, errors
