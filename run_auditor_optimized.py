#!/usr/bin/env python3
"""
Optimized password auditor with efficient hash-based reuse detection.
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
from password_auditor.reporting.visualizer import PasswordVisualizer

def analyze_with_optimized_reuse(csv_file, max_passwords=10000):
    """Analyze passwords with optimized hash-based reuse detection."""
    
    print(f"🚀 Optimized Password Analysis with Hash-Based Reuse Detection")
    print(f"Loading data from: {csv_file}")
    
    # Load data
    csv_handler = CSVHandler()
    all_data = csv_handler.read_password_csv(csv_file)
    total_passwords = len(all_data)
    
    if total_passwords > max_passwords:
        print(f"📊 Large dataset ({total_passwords} passwords). Analyzing first {max_passwords}...")
        password_data = all_data[:max_passwords]
    else:
        password_data = all_data
    
    print(f"🔍 Analyzing {len(password_data)} passwords with optimized reuse detection...")
    
    # Initialize analyzer
    analyzer = PasswordAnalyzer()
    
    # Run analysis with optimized reuse detection
    results = analyzer.analyze_passwords(password_data)
    
    # Get statistics
    stats = analyzer.get_summary_statistics()
    
    # Print results
    report_generator = ReportGenerator()
    report_generator.print_summary(stats)
    
    # Show top weak passwords
    print(f"\n--- Top 15 Weakest Passwords ---")
    weak_passwords = analyzer.get_top_weak_passwords(15)
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
        print("Usage: python3 run_auditor_optimized.py <csv_file> [max_passwords]")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    # Parse max_passwords from arguments, skipping any flags
    max_passwords = 10000
    for arg in sys.argv[2:]:
        if arg.isdigit():
            max_passwords = int(arg)
            break
    
    try:
        results, stats = analyze_with_optimized_reuse(csv_file, max_passwords)
        print(f"\n✅ Optimized analysis completed successfully!")
        print(f"📊 Analyzed {len(results)} passwords with O(n) reuse detection")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        sys.exit(1)
