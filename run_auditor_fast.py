#!/usr/bin/env python3
"""
Fast version of the password auditor for large datasets.
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from password_auditor.core.analyzer import PasswordAnalyzer
from password_auditor.utils.csv_handler import CSVHandler
from password_auditor.reporting.report_generator import ReportGenerator

def analyze_large_dataset(csv_file, max_passwords=1000):
    """Analyze a large dataset with optimizations."""
    
    print(f"Loading password data from {csv_file}...")
    csv_handler = CSVHandler()
    
    # Load all data
    all_data = csv_handler.read_password_csv(csv_file)
    total_passwords = len(all_data)
    
    print(f"Total passwords: {total_passwords}")
    
    if total_passwords > max_passwords:
        print(f"Large dataset detected. Analyzing first {max_passwords} passwords for performance...")
        password_data = all_data[:max_passwords]
    else:
        password_data = all_data
    
    print(f"Analyzing {len(password_data)} passwords...")
    
    # Initialize analyzer with optimizations
    analyzer = PasswordAnalyzer()
    
    # Run analysis
    results = analyzer.analyze_passwords(password_data)
    
    # Generate summary
    stats = analyzer.get_summary_statistics()
    
    # Print results
    report_generator = ReportGenerator()
    report_generator.print_summary(stats)
    
    # Show top weak passwords
    print(f"\n--- Top 10 Weakest Passwords ---")
    weak_passwords = analyzer.get_top_weak_passwords(10)
    report_generator.print_password_list(weak_passwords, show_details=True)
    
    # Show top strong passwords
    print(f"\n--- Top 10 Strongest Passwords ---")
    strong_passwords = analyzer.get_top_strong_passwords(10)
    report_generator.print_password_list(strong_passwords, show_details=True)
    
    # Show security recommendations
    report_generator.print_security_recommendations(results, stats)
    
    return results, stats

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 run_auditor_fast.py <csv_file> [max_passwords]")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    max_passwords = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
    
    try:
        results, stats = analyze_large_dataset(csv_file, max_passwords)
        print(f"\n✅ Analysis completed successfully!")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        sys.exit(1)
