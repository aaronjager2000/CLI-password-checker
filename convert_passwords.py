#!/usr/bin/env python3
"""
Convert password-only CSV to username/password format for the auditor.
"""

import csv
import sys

def convert_password_csv(input_file, output_file):
    """Convert a password-only CSV to username/password format."""
    
    with open(input_file, 'r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        
        # Check if 'password' column exists
        if 'password' not in reader.fieldnames:
            print(f"Error: 'password' column not found in {input_file}")
            print(f"Available columns: {', '.join(reader.fieldnames)}")
            return False
        
        with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(['username', 'password', 'notes'])
            
            for i, row in enumerate(reader, 1):
                password = row['password'].strip('"')  # Remove quotes if present
                username = f"user_{i:04d}"  # Generate username like user_0001
                notes = f"Password from {input_file}"
                writer.writerow([username, password, notes])
    
    print(f"Converted {i} passwords from {input_file} to {output_file}")
    return True

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 convert_passwords.py <input_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if convert_password_csv(input_file, output_file):
        print(f"Conversion successful! You can now run:")
        print(f"python3 run_auditor.py {output_file} --visualize")
    else:
        sys.exit(1)
