"""
CSV handling utilities for password data.
"""

import csv
import sys
from typing import List, Tuple, Optional
from pathlib import Path


class CSVHandler:
    """Handles CSV input/output operations for password data."""
    
    def __init__(self):
        self.required_columns = ['username', 'password']
        self.optional_columns = ['email', 'domain', 'notes']
    
    def read_password_csv(self, file_path: str) -> List[Tuple[str, str]]:
        """
        Read password data from CSV file.
        
        Args:
            file_path: Path to the CSV file
            
        Returns:
            List of (username, password) tuples
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If CSV format is invalid
        """
        if not Path(file_path).exists():
            raise FileNotFoundError(f"CSV file not found: {file_path}")
        
        password_data = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as csvfile:
                # Try to detect delimiter
                sample = csvfile.read(1024)
                csvfile.seek(0)
                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff(sample).delimiter
                
                reader = csv.DictReader(csvfile, delimiter=delimiter)
                
                # Validate required columns
                if not all(col in reader.fieldnames for col in self.required_columns):
                    raise ValueError(
                        f"CSV must contain columns: {', '.join(self.required_columns)}. "
                        f"Found: {', '.join(reader.fieldnames)}"
                    )
                
                for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
                    username = row.get('username', '').strip()
                    password = row.get('password', '').strip()
                    
                    if not username or not password:
                        print(f"Warning: Skipping row {row_num} - missing username or password", 
                              file=sys.stderr)
                        continue
                    
                    password_data.append((username, password))
        
        except Exception as e:
            raise ValueError(f"Error reading CSV file: {str(e)}")
        
        if not password_data:
            raise ValueError("No valid password data found in CSV file")
        
        return password_data
    
    def write_results_csv(self, results: List[dict], output_path: str) -> None:
        """
        Write analysis results to CSV file.
        
        Args:
            results: List of analysis result dictionaries
            output_path: Path to output CSV file
        """
        if not results:
            raise ValueError("No results to write")
        
        fieldnames = [
            'username', 'password', 'total_score', 'strength_category',
            'entropy_score', 'entropy_bits', 'dictionary_score', 'reuse_score',
            'common_passwords', 'dictionary_words', 'keyboard_patterns',
            'sequential_patterns', 'exact_duplicates', 'similar_passwords'
        ]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Flatten nested data for CSV
                row = {
                    'username': result['username'],
                    'password': result['password'],
                    'total_score': result['total_score'],
                    'strength_category': result['strength_category'],
                    'entropy_score': result['scores']['entropy'],
                    'entropy_bits': result['entropy']['entropy_bits'],
                    'dictionary_score': result['scores']['dictionary'],
                    'reuse_score': result['scores']['reuse'],
                    'common_passwords': ', '.join(result['dictionary']['common_passwords']),
                    'dictionary_words': ', '.join(result['dictionary']['dictionary_words']),
                    'keyboard_patterns': ', '.join(result['dictionary']['keyboard_patterns']),
                    'sequential_patterns': ', '.join(result['dictionary']['sequential_patterns']),
                    'exact_duplicates': result['reuse']['exact_duplicates'],
                    'similar_passwords': result['reuse']['similar_passwords']
                }
                writer.writerow(row)
    
    def create_sample_csv(self, output_path: str, num_samples: int = 20) -> None:
        """
        Create a sample CSV file with example password data.
        
        Args:
            output_path: Path to create the sample CSV
            num_samples: Number of sample entries to create
        """
        sample_data = [
            ('john_doe', 'password123'),
            ('jane_smith', 'qwerty'),
            ('admin_user', 'admin'),
            ('test_user', '123456'),
            ('demo_user', 'letmein'),
            ('user1', 'welcome'),
            ('user2', 'monkey'),
            ('user3', 'dragon'),
            ('user4', 'master'),
            ('user5', 'hello'),
            ('user6', 'freedom'),
            ('user7', 'whatever'),
            ('user8', 'qazwsx'),
            ('user9', 'trustno1'),
            ('user10', '654321'),
            ('user11', 'jordan23'),
            ('user12', 'harley'),
            ('user13', 'shadow'),
            ('user14', 'superman'),
            ('user15', 'michael'),
            ('user16', 'football'),
            ('user17', 'jordan'),
            ('user18', 'hunter'),
            ('user19', 'ranger'),
            ('user20', 'daniel'),
            ('strong_user1', 'Kj9#mN2$pL8@vR5!'),
            ('strong_user2', 'Xy7&wQ4*zB1%nM6+'),
            ('strong_user3', 'Fg3@hJ9#kL2$mP5!'),
            ('strong_user4', 'Rt8&uI4*zO1%pA6+'),
            ('strong_user5', 'Vb7@cN2#dF5$gH8!')
        ]
        
        # Take only the requested number of samples
        sample_data = sample_data[:num_samples]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['username', 'password', 'notes']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for username, password in sample_data:
                notes = 'Sample data for testing'
                if 'strong' in username:
                    notes = 'Strong password example'
                elif username in ['john_doe', 'jane_smith', 'admin_user']:
                    notes = 'Common weak password'
                
                writer.writerow({
                    'username': username,
                    'password': password,
                    'notes': notes
                })
    
    def validate_csv_format(self, file_path: str) -> Tuple[bool, List[str]]:
        """
        Validate CSV file format without reading all data.
        
        Args:
            file_path: Path to the CSV file
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        if not Path(file_path).exists():
            errors.append(f"File not found: {file_path}")
            return False, errors
        
        try:
            with open(file_path, 'r', encoding='utf-8') as csvfile:
                # Read first few lines to validate format
                sample = csvfile.read(1024)
                csvfile.seek(0)
                
                if not sample.strip():
                    errors.append("CSV file is empty")
                    return False, errors
                
                # Try to detect delimiter
                sniffer = csv.Sniffer()
                try:
                    delimiter = sniffer.sniff(sample).delimiter
                except csv.Error:
                    errors.append("Could not detect CSV delimiter")
                    return False, errors
                
                # Read header
                reader = csv.DictReader(csvfile, delimiter=delimiter)
                
                if not reader.fieldnames:
                    errors.append("CSV file has no header row")
                    return False, errors
                
                # Check required columns
                missing_columns = [col for col in self.required_columns 
                                 if col not in reader.fieldnames]
                if missing_columns:
                    errors.append(f"Missing required columns: {', '.join(missing_columns)}")
                
                # Check for empty rows
                row_count = 0
                for row in reader:
                    row_count += 1
                    if row_count > 5:  # Only check first 5 rows for validation
                        break
                    
                    if not any(row.values()):
                        errors.append(f"Empty row found at line {row_count + 1}")
                
                if row_count == 0:
                    errors.append("No data rows found in CSV file")
        
        except Exception as e:
            errors.append(f"Error reading CSV file: {str(e)}")
        
        return len(errors) == 0, errors
