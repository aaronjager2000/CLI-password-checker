#!/usr/bin/env python3
"""
Demo script for the Password Strength Auditor.
"""

import os
import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from password_auditor.main import main

def run_demo():
    """Run a demonstration of the password auditor."""
    print("🔐 Password Strength Auditor Demo")
    print("=" * 50)
    
    # Create sample data
    sample_file = "demo_passwords.csv"
    print(f"Creating sample data file: {sample_file}")
    
    # Run the create-sample command
    sys.argv = ['demo.py', '--create-sample', sample_file]
    main()
    
    print("\n" + "=" * 50)
    print("Running password analysis...")
    
    # Run the analysis
    sys.argv = ['demo.py', sample_file, '--visualize', '--top-weak', '5', '--top-strong', '3']
    main()
    
    print("\n" + "=" * 50)
    print("Demo completed!")
    print(f"Check the generated files:")
    print(f"- {sample_file} (sample data)")
    print(f"- *.png files (visualization charts)")
    
    # Clean up
    if os.path.exists(sample_file):
        print(f"\nCleaning up {sample_file}...")
        os.remove(sample_file)

if __name__ == '__main__':
    run_demo()
