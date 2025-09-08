#!/usr/bin/env python3
"""
Quick password auditor that skips expensive reuse detection for large datasets.
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from password_auditor.core.entropy import EntropyCalculator
from password_auditor.core.dictionary import DictionaryChecker
from password_auditor.utils.csv_handler import CSVHandler

def quick_analyze_passwords(csv_file, max_passwords=5000):
    """Quick analysis without expensive reuse detection."""
    
    print(f"🚀 Quick Password Analysis")
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
    
    print(f"🔍 Analyzing {len(password_data)} passwords...")
    
    # Initialize analyzers
    entropy_calc = EntropyCalculator()
    dict_checker = DictionaryChecker()
    
    results = []
    
    # Analyze each password
    for i, (username, password) in enumerate(password_data):
        if i % 100 == 0:
            print(f"   Progress: {i}/{len(password_data)} ({i/len(password_data)*100:.1f}%)")
        
        # Calculate entropy score
        entropy_bits, entropy_score = entropy_calc.calculate_entropy_score(password)
        
        # Calculate dictionary score
        dict_score, dict_analysis = dict_checker.calculate_dictionary_score(password, username)
        
        # Skip reuse detection for speed (set to max score)
        reuse_score = 30
        
        # Calculate total score
        total_score = entropy_score + dict_score + reuse_score
        
        # Determine strength category
        if total_score >= 80:
            category = "Very Strong"
        elif total_score >= 60:
            category = "Strong"
        elif total_score >= 40:
            category = "Medium"
        elif total_score >= 20:
            category = "Weak"
        else:
            category = "Very Weak"
        
        results.append({
            'username': username,
            'password': password,
            'total_score': total_score,
            'strength_category': category,
            'entropy_score': entropy_score,
            'dictionary_score': dict_score,
            'reuse_score': reuse_score,
            'entropy_bits': entropy_bits,
            'is_common_password': len(dict_analysis['common_passwords']) > 0,
            'has_dictionary_words': len(dict_analysis['dictionary_words']) > 0,
            'has_keyboard_patterns': len(dict_analysis['keyboard_patterns']) > 0
        })
    
    # Sort by score (weakest first)
    results.sort(key=lambda x: x['total_score'])
    
    # Calculate statistics
    scores = [r['total_score'] for r in results]
    avg_score = sum(scores) / len(scores)
    min_score = min(scores)
    max_score = max(scores)
    
    # Count by category
    category_counts = {}
    for result in results:
        category = result['strength_category']
        category_counts[category] = category_counts.get(category, 0) + 1
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"📊 QUICK PASSWORD ANALYSIS RESULTS")
    print(f"{'='*60}")
    print(f"Total Passwords Analyzed: {len(results)}")
    print(f"Average Security Score: {avg_score:.1f}/100")
    print(f"Score Range: {min_score} - {max_score}")
    
    print(f"\n📈 Strength Distribution:")
    for category, count in sorted(category_counts.items()):
        percentage = (count / len(results)) * 100
        emoji = {"Very Weak": "🔴", "Weak": "🟠", "Medium": "🟡", "Strong": "🟢", "Very Strong": "🔵"}.get(category, "⚪")
        print(f"  {emoji} {category}: {count} ({percentage:.1f}%)")
    
    # Show top weak passwords
    print(f"\n🚨 Top 10 Weakest Passwords:")
    print(f"{'-'*80}")
    for i, result in enumerate(results[:10], 1):
        emoji = {"Very Weak": "🔴", "Weak": "🟠", "Medium": "🟡", "Strong": "🟢", "Very Strong": "🔵"}.get(result['strength_category'], "⚪")
        print(f"{i:2d}. {emoji} {result['username']:<15} Score: {result['total_score']:2d}/100 ({result['strength_category']})")
        print(f"     Password: {result['password']}")
        if result['is_common_password']:
            print(f"     ⚠️  Common password detected")
        if result['has_dictionary_words']:
            print(f"     ⚠️  Contains dictionary words")
        if result['has_keyboard_patterns']:
            print(f"     ⚠️  Contains keyboard patterns")
        print()
    
    # Show top strong passwords
    print(f"\n💪 Top 10 Strongest Passwords:")
    print(f"{'-'*80}")
    for i, result in enumerate(results[-10:][::-1], 1):
        emoji = {"Very Weak": "🔴", "Weak": "🟠", "Medium": "🟡", "Strong": "🟢", "Very Strong": "🔵"}.get(result['strength_category'], "⚪")
        print(f"{i:2d}. {emoji} {result['username']:<15} Score: {result['total_score']:2d}/100 ({result['strength_category']})")
        print(f"     Password: {result['password']}")
        print()
    
    # Security insights
    weak_count = category_counts.get('Very Weak', 0) + category_counts.get('Weak', 0)
    common_count = sum(1 for r in results if r['is_common_password'])
    dict_count = sum(1 for r in results if r['has_dictionary_words'])
    keyboard_count = sum(1 for r in results if r['has_keyboard_patterns'])
    
    print(f"\n🔍 Security Insights:")
    print(f"  • {weak_count} passwords are weak or very weak")
    print(f"  • {common_count} passwords are in common password lists")
    print(f"  • {dict_count} passwords contain dictionary words")
    print(f"  • {keyboard_count} passwords contain keyboard patterns")
    
    print(f"\n✅ Quick analysis completed in seconds!")
    return results

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 run_auditor_quick.py <csv_file> [max_passwords]")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    max_passwords = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    
    try:
        results = quick_analyze_passwords(csv_file, max_passwords)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
