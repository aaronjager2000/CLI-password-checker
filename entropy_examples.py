#!/usr/bin/env python3
"""
Practical examples demonstrating entropy calculations and password scoring.
"""

import sys
import os
from pathlib import Path

# Add the current directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from password_auditor.core.entropy import EntropyCalculator
from password_auditor.core.dictionary import DictionaryChecker
from password_auditor.core.reuse_detector import ReuseDetector

def demonstrate_entropy_calculations():
    """Demonstrate entropy calculations with detailed explanations."""
    
    print("=" * 80)
    print("ENTROPY CALCULATION EXAMPLES")
    print("=" * 80)
    
    calculator = EntropyCalculator()
    
    examples = [
        "123456",
        "aaaaaa", 
        "aB3!xY9",
        "password",
        "MyStr0ng!P@ssw0rd",
        "qwerty",
        "abc123",
        "P@ssw0rd123!"
    ]
    
    for password in examples:
        print(f"\nPassword: '{password}'")
        print("-" * 50)
        
        # Calculate entropy
        entropy = calculator.calculate_entropy(password)
        print(f"Shannon Entropy: {entropy:.3f} bits")
        
        # Character set analysis
        char_sets = calculator.analyze_character_sets(password)
        print(f"Character Sets: {[k for k, v in char_sets.items() if v]}")
        
        # Pattern detection
        patterns = calculator.detect_patterns(password)
        detected_patterns = [k for k, v in patterns.items() if v]
        print(f"Detected Patterns: {detected_patterns if detected_patterns else 'None'}")
        
        # Calculate entropy score
        entropy_bits, entropy_score = calculator.calculate_entropy_score(password)
        print(f"Entropy Score: {entropy_score}/40 points")
        
        # Detailed breakdown
        print(f"  - Base entropy: {entropy_bits:.3f} × 2 = {entropy_bits * 2:.1f} points")
        print(f"  - Character sets: {sum(char_sets.values())} sets × 2 = {sum(char_sets.values()) * 2} points")
        print(f"  - Length bonus: {len(password)} × 0.5 = {min(len(password) * 0.5, 10):.1f} points")
        print(f"  - Pattern penalty: {len(detected_patterns)} × 3 = {len(detected_patterns) * 3} points")

def demonstrate_dictionary_analysis():
    """Demonstrate dictionary analysis with detailed explanations."""
    
    print("\n" + "=" * 80)
    print("DICTIONARY ANALYSIS EXAMPLES")
    print("=" * 80)
    
    checker = DictionaryChecker()
    
    examples = [
        ("password", "user1"),
        ("l0v3", "user2"),
        ("qwerty123", "user3"),
        ("MyStr0ng!P@ssw0rd", "user4"),
        ("abc123", "user5"),
        ("football", "user6")
    ]
    
    for password, username in examples:
        print(f"\nPassword: '{password}' (User: {username})")
        print("-" * 50)
        
        # Calculate dictionary score
        dict_score, analysis = checker.calculate_dictionary_score(password, username)
        print(f"Dictionary Score: {dict_score}/30 points")
        
        # Detailed analysis
        if analysis['common_passwords']:
            print(f"  - Common password: -20 points")
        if analysis['dictionary_words']:
            print(f"  - Dictionary words: {analysis['dictionary_words']} (-{len(analysis['dictionary_words']) * 3} points)")
        if analysis['leet_speak']:
            print(f"  - Leet speak detected: -5 points")
        if analysis['keyboard_patterns']:
            print(f"  - Keyboard patterns: {analysis['keyboard_patterns']} (-{len(analysis['keyboard_patterns']) * 4} points)")
        if analysis['sequential_patterns']:
            print(f"  - Sequential patterns: {analysis['sequential_patterns']} (-{len(analysis['sequential_patterns']) * 3} points)")
        if analysis['personal_info']:
            print(f"  - Personal info: {analysis['personal_info']} (-{len(analysis['personal_info']) * 2} points)")

def demonstrate_complete_scoring():
    """Demonstrate complete password scoring with all components."""
    
    print("\n" + "=" * 80)
    print("COMPLETE PASSWORD SCORING EXAMPLES")
    print("=" * 80)
    
    calculator = EntropyCalculator()
    checker = DictionaryChecker()
    reuse_detector = ReuseDetector()
    
    examples = [
        ("123456", "user1"),
        ("password", "user2"),
        ("MyStr0ng!P@ssw0rd", "user3"),
        ("qwerty123", "user4"),
        ("abc123", "user5")
    ]
    
    for password, username in examples:
        print(f"\nPassword: '{password}' (User: {username})")
        print("=" * 60)
        
        # Add to reuse detector
        reuse_detector.add_password(username, password)
        
        # Calculate all scores
        entropy_bits, entropy_score = calculator.calculate_entropy_score(password)
        dict_score, dict_analysis = checker.calculate_dictionary_score(password, username)
        reuse_score, reuse_analysis = reuse_detector.calculate_reuse_score(username, password)
        
        total_score = entropy_score + dict_score + reuse_score
        
        # Determine category
        if total_score >= 80:
            category = "Very Strong"
            emoji = "🔵"
        elif total_score >= 60:
            category = "Strong"
            emoji = "🟢"
        elif total_score >= 40:
            category = "Medium"
            emoji = "🟡"
        elif total_score >= 20:
            category = "Weak"
            emoji = "🟠"
        else:
            category = "Very Weak"
            emoji = "🔴"
        
        print(f"TOTAL SCORE: {total_score}/100 ({emoji} {category})")
        print(f"├── Entropy Score: {entropy_score}/40")
        print(f"├── Dictionary Score: {dict_score}/30")
        print(f"└── Reuse Score: {reuse_score}/30")
        
        # Show issues
        issues = []
        if dict_analysis['common_passwords']:
            issues.append("Common password")
        if dict_analysis['dictionary_words']:
            issues.append("Dictionary words")
        if dict_analysis['keyboard_patterns']:
            issues.append("Keyboard patterns")
        if reuse_analysis['exact_duplicates'] > 0:
            issues.append(f"Exact duplicate ({reuse_analysis['exact_duplicates']} copies)")
        
        if issues:
            print(f"Issues: {'; '.join(issues)}")
        else:
            print("No major issues detected")

def demonstrate_entropy_formula():
    """Demonstrate the Shannon entropy formula with step-by-step calculations."""
    
    print("\n" + "=" * 80)
    print("SHANNON ENTROPY FORMULA DEMONSTRATION")
    print("=" * 80)
    
    password = "123456"
    print(f"Password: '{password}'")
    print("\nStep-by-step entropy calculation:")
    print("Formula: H(X) = -Σ P(xi) × log₂(P(xi))")
    print()
    
    # Count characters
    char_counts = {}
    for char in password:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    print("Character frequencies:")
    for char, count in char_counts.items():
        print(f"  '{char}': {count} times")
    
    print(f"\nPassword length: {len(password)}")
    print("\nProbability calculations:")
    
    total_entropy = 0.0
    for char, count in char_counts.items():
        probability = count / len(password)
        log_prob = math.log2(probability) if probability > 0 else 0
        entropy_contribution = -probability * log_prob
        total_entropy += entropy_contribution
        
        print(f"  P('{char}') = {count}/{len(password)} = {probability:.3f}")
        print(f"  log₂({probability:.3f}) = {log_prob:.3f}")
        print(f"  -{probability:.3f} × {log_prob:.3f} = {entropy_contribution:.3f}")
        print()
    
    print(f"Total Entropy: {total_entropy:.3f} bits")
    
    # Compare with different passwords
    print(f"\nComparison with other passwords:")
    passwords = ["aaaaaa", "aB3!xY9", "password"]
    for pwd in passwords:
        char_counts = {}
        for char in pwd:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        for char, count in char_counts.items():
            probability = count / len(pwd)
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        print(f"  '{pwd}': {entropy:.3f} bits")

if __name__ == "__main__":
    import math
    
    print("PASSWORD ENTROPY AND SCORING DEMONSTRATION")
    print("=" * 80)
    
    try:
        demonstrate_entropy_formula()
        demonstrate_entropy_calculations()
        demonstrate_dictionary_analysis()
        demonstrate_complete_scoring()
        
        print("\n" + "=" * 80)
        print("DEMONSTRATION COMPLETED")
        print("=" * 80)
        
    except Exception as e:
        print(f"Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
