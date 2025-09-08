# Password Entropy and Strength Calculation Documentation

## Table of Contents

1. [Introduction](#introduction)
2. [Shannon Entropy Theory](#shannon-entropy-theory)
3. [Entropy Calculation Implementation](#entropy-calculation-implementation)
4. [Password Strength Scoring System](#password-strength-scoring-system)
5. [Character Set Analysis](#character-set-analysis)
6. [Pattern Detection](#pattern-detection)
7. [Dictionary Analysis](#dictionary-analysis)
8. [Reuse Detection](#reuse-detection)
9. [Complete Scoring Algorithm](#complete-scoring-algorithm)
10. [Examples and Case Studies](#examples-and-case-studies)
11. [Performance Considerations](#performance-considerations)

---

## Introduction

The Password Strength Auditor uses a sophisticated multi-component scoring system based on information theory, specifically Shannon entropy, combined with practical security heuristics. This document provides a comprehensive explanation of how entropy is calculated and how the final password strength score is determined.

---

## Shannon Entropy Theory

### What is Entropy?

Entropy, in the context of information theory, measures the uncertainty or randomness in a message. For passwords, entropy quantifies how difficult it is to guess the password through brute force attacks.

### Mathematical Foundation

Shannon entropy is calculated using the formula:

```
H(X) = -Σ P(xi) × log₂(P(xi))
```

Where:

- `H(X)` is the entropy in bits
- `P(xi)` is the probability of character `xi` appearing
- The sum is over all possible characters in the password

### Why Entropy Matters for Passwords

Higher entropy means:

- More randomness in character distribution
- Harder to predict or guess
- More resistant to brute force attacks
- Better security against dictionary attacks

---

## Entropy Calculation Implementation

### Core Entropy Function

```python
def calculate_entropy(self, password: str) -> float:
    """Calculate Shannon entropy of a password."""
    if not password:
        return 0.0

    # Count character frequencies
    char_counts = {}
    for char in password:
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate entropy
    entropy = 0.0
    password_length = len(password)

    for count in char_counts.values():
        probability = count / password_length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy
```

### Step-by-Step Process

1. **Character Frequency Analysis**: Count how many times each character appears
2. **Probability Calculation**: Divide each character count by total password length
3. **Entropy Summation**: Apply Shannon's formula for each character
4. **Result**: Return entropy in bits

### Example Calculations

#### Example 1: "123456"

- Characters: `1`, `2`, `3`, `4`, `5`, `6` (each appears once)
- Probabilities: Each character has probability 1/6 = 0.167
- Entropy: `-6 × (0.167 × log₂(0.167)) = 2.585 bits`

#### Example 2: "aaaaaa"

- Characters: Only `a` appears (6 times)
- Probability: `a` has probability 6/6 = 1.0
- Entropy: `-1 × (1.0 × log₂(1.0)) = 0 bits` (no randomness)

#### Example 3: "aB3!xY9"

- Characters: All different, each appears once
- Probabilities: Each character has probability 1/7 = 0.143
- Entropy: `-7 × (0.143 × log₂(0.143)) = 2.807 bits`

---

## Password Strength Scoring System

The password strength is calculated using a three-component system with a total possible score of 100 points:

### Component Breakdown

| Component            | Max Points | Purpose                                   |
| -------------------- | ---------- | ----------------------------------------- |
| **Entropy Score**    | 40 points  | Measures randomness and unpredictability  |
| **Dictionary Score** | 30 points  | Penalizes common words and patterns       |
| **Reuse Score**      | 30 points  | Penalizes duplicate and similar passwords |

### Final Strength Categories

| Score Range | Category    | Description                                         |
| ----------- | ----------- | --------------------------------------------------- |
| 80-100      | Very Strong | Excellent security, highly resistant to attacks     |
| 60-79       | Strong      | Good security, suitable for most applications       |
| 40-59       | Medium      | Moderate security, acceptable for low-risk accounts |
| 20-39       | Weak        | Poor security, should be changed                    |
| 0-19        | Very Weak   | Critical security risk, immediate change required   |

---

## Character Set Analysis

### Character Set Categories

The system recognizes five character set categories:

```python
self.char_sets = {
    'lowercase': set('abcdefghijklmnopqrstuvwxyz'),      # 26 characters
    'uppercase': set('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),      # 26 characters
    'digits': set('0123456789'),                         # 10 characters
    'special': set('!@#$%^&*()_+-=[]{}|;:,.<>?'),       # 32 characters
    'space': set(' ')                                    # 1 character
}
```

### Character Set Scoring

- **Bonus Points**: 2 points per character set present
- **Maximum Bonus**: 10 points (5 sets × 2 points)
- **Rationale**: More character sets = larger search space = harder to crack

### Examples

| Password       | Character Sets                           | Bonus Points |
| -------------- | ---------------------------------------- | ------------ |
| "password"     | lowercase only                           | 2 points     |
| "Password"     | lowercase + uppercase                    | 4 points     |
| "Password123"  | lowercase + uppercase + digits           | 6 points     |
| "Password123!" | lowercase + uppercase + digits + special | 8 points     |

---

## Pattern Detection

### Detected Patterns

The system identifies five types of problematic patterns:

#### 1. Sequential Characters

```python
def _has_sequential_chars(self, password: str) -> bool:
    """Check for sequential characters (abc, 123, etc.)."""
    for i in range(len(password) - 2):
        if (ord(password[i+1]) == ord(password[i]) + 1 and
            ord(password[i+2]) == ord(password[i]) + 2):
            return True
    return False
```

**Examples**: "abc", "123", "XYZ", "789"

#### 2. Repeated Characters

```python
def _has_repeated_chars(self, password: str) -> bool:
    """Check for repeated character sequences."""
    for i in range(len(password) - 1):
        if password[i] == password[i+1]:
            return True
    return False
```

**Examples**: "aa", "11", "bbbb"

#### 3. Keyboard Patterns

```python
keyboard_rows = [
    'qwertyuiop',
    'asdfghjkl',
    'zxcvbnm',
    '1234567890'
]
```

**Examples**: "qwerty", "asdf", "zxcv", "123456"

#### 4. Date Patterns

```python
date_patterns = [
    r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}',  # MM/DD/YYYY
    r'\d{4}[/-]\d{1,2}[/-]\d{1,2}',    # YYYY/MM/DD
    r'\d{6,8}',                         # YYYYMMDD or MMDDYYYY
]
```

**Examples**: "12/25/2023", "20231225", "12252023"

#### 5. Phone Number Patterns

```python
phone_pattern = r'\d{3}[-.]?\d{3}[-.]?\d{4}'
```

**Examples**: "555-123-4567", "555.123.4567", "5551234567"

### Pattern Penalties

- **Penalty per Pattern**: 3 points
- **Maximum Penalty**: 15 points (5 patterns × 3 points)
- **Rationale**: Patterns make passwords predictable and easier to guess

---

## Dictionary Analysis

### Dictionary Components

#### 1. Common Password Detection

- **Built-in List**: 60+ most common passwords
- **External Dictionary**: Custom dictionary file support
- **Major Penalty**: 20 points for common passwords

#### 2. Dictionary Word Detection

- **Word List**: 50+ common English words
- **Penalty**: 3 points per detected word
- **Examples**: "love", "life", "happy", "dream"

#### 3. Leet Speak Detection

- **Character Mapping**: `a→4`, `e→3`, `i→1`, `o→0`, `s→5`
- **Penalty**: 5 points for leet speak usage
- **Examples**: "l0v3", "p4ssw0rd"

#### 4. Keyboard Pattern Detection

- **Pattern List**: Common keyboard sequences
- **Penalty**: 4 points per pattern
- **Examples**: "qwerty", "asdfgh", "zxcvbn"

#### 5. Sequential Pattern Detection

- **Detection**: Consecutive numbers/letters
- **Penalty**: 3 points per pattern
- **Examples**: "123", "abc", "456"

#### 6. Personal Information Detection

- **Username Inclusion**: Password contains username
- **Date Patterns**: Birth years, dates
- **Phone Patterns**: Phone numbers
- **Penalty**: 2 points per pattern

### Dictionary Scoring Algorithm

```python
def calculate_dictionary_score(self, password: str, username: str = None) -> Tuple[int, Dict]:
    score = 30  # Start with full points

    # Check common passwords (major penalty)
    if self.check_common_passwords(password):
        score -= 20

    # Check dictionary words
    dict_words = self.check_dictionary_words(password)
    score -= len(dict_words) * 3

    # Check leet speak
    if self.check_leet_speak(password):
        score -= 5

    # Check keyboard patterns
    keyboard_patterns = self.check_keyboard_patterns(password)
    score -= len(keyboard_patterns) * 4

    # Check sequential patterns
    sequential_patterns = self.check_sequential_patterns(password)
    score -= len(sequential_patterns) * 3

    # Check personal info
    personal_patterns = self.check_personal_info_patterns(password, username)
    score -= len(personal_patterns) * 2

    return max(0, score), analysis
```

---

## Reuse Detection

### Hash-Based Detection Algorithm

The system uses an efficient O(n) hash-based approach for reuse detection:

```python
def is_password_reused(self, password: str) -> Tuple[bool, int]:
    """Efficiently check if a password is reused using hash-based detection."""
    password_hash = self._hash_password(password)

    # O(1) lookup in hash set
    if password_hash in self.hash_set:
        duplicate_count = len(self.password_hashes[password_hash])
        return True, duplicate_count

    return False, 0
```

### Reuse Scoring

- **Exact Duplicates**: 5 points penalty per duplicate (max 15 points)
- **User Reuse**: 10 points penalty for same user reusing passwords
- **Similar Passwords**: Skipped for performance (O(n²) complexity)

### Performance Optimization

| Method               | Time Complexity | Space Complexity | Use Case          |
| -------------------- | --------------- | ---------------- | ----------------- |
| Hash-based Detection | O(n)            | O(n)             | Production (Fast) |
| Similarity Detection | O(n²)           | O(n²)            | Research (Slow)   |

---

## Complete Scoring Algorithm

### Entropy Score Calculation (0-40 points)

```python
def calculate_entropy_score(self, password: str) -> Tuple[float, int]:
    # Base entropy calculation
    entropy = self.calculate_entropy(password)

    # Character set analysis
    char_sets = self.analyze_character_sets(password)
    set_bonus = sum(char_sets.values()) * 2  # 2 points per character set

    # Length bonus
    length_bonus = min(len(password) * 0.5, 10)  # Max 10 points for length

    # Pattern penalties
    patterns = self.detect_patterns(password)
    pattern_penalty = sum(patterns.values()) * 3  # 3 points penalty per pattern

    # Calculate final score (0-40 scale)
    base_score = min(entropy * 2, 20)  # Max 20 points for entropy
    final_score = max(0, base_score + set_bonus + length_bonus - pattern_penalty)
    final_score = min(final_score, 40)  # Cap at 40

    return entropy, int(final_score)
```

### Final Score Calculation

```python
def analyze_password(self, username: str, password: str) -> Dict:
    # Calculate entropy score (0-40)
    entropy_bits, entropy_score = self.entropy_calculator.calculate_entropy_score(password)

    # Calculate dictionary score (0-30)
    dict_score, dict_analysis = self.dictionary_checker.calculate_dictionary_score(password, username)

    # Calculate reuse score (0-30)
    reuse_score, reuse_analysis = self.reuse_detector.calculate_reuse_score(username, password)

    # Calculate total score
    total_score = entropy_score + dict_score + reuse_score

    # Determine strength category
    strength_category = self._categorize_strength(total_score)

    return {
        'total_score': total_score,
        'strength_category': strength_category,
        'scores': {
            'entropy': entropy_score,
            'dictionary': dict_score,
            'reuse': reuse_score
        }
    }
```

---

## Examples and Case Studies

### Example 1: "123456" (Very Weak)

**Entropy Analysis:**

- Entropy: 2.585 bits
- Character sets: digits only (1 set)
- Patterns: sequential, keyboard pattern
- Length: 6 characters

**Scoring:**

- Base entropy: 2.585 × 2 = 5.17 points
- Character set bonus: 1 × 2 = 2 points
- Length bonus: 6 × 0.5 = 3 points
- Pattern penalty: 2 × 3 = 6 points
- **Entropy Score**: 5.17 + 2 + 3 - 6 = 4.17 → 4 points

**Dictionary Analysis:**

- Common password: -20 points
- Keyboard pattern: -4 points
- **Dictionary Score**: 30 - 20 - 4 = 6 points

**Reuse Analysis:**

- Assume 3 duplicates: -15 points
- **Reuse Score**: 30 - 15 = 15 points

**Total Score**: 4 + 6 + 15 = 25 points (Weak)

### Example 2: "MyStr0ng!P@ssw0rd" (Strong)

**Entropy Analysis:**

- Entropy: 3.32 bits
- Character sets: lowercase, uppercase, digits, special (4 sets)
- Patterns: none detected
- Length: 16 characters

**Scoring:**

- Base entropy: 3.32 × 2 = 6.64 points
- Character set bonus: 4 × 2 = 8 points
- Length bonus: 16 × 0.5 = 8 points (capped at 10)
- Pattern penalty: 0 points
- **Entropy Score**: 6.64 + 8 + 8 = 22.64 → 23 points

**Dictionary Analysis:**

- No common passwords: 0 penalty
- No dictionary words: 0 penalty
- No patterns: 0 penalty
- **Dictionary Score**: 30 points

**Reuse Analysis:**

- No duplicates: 0 penalty
- **Reuse Score**: 30 points

**Total Score**: 23 + 30 + 30 = 83 points (Very Strong)

### Example 3: "password123" (Medium)

**Entropy Analysis:**

- Entropy: 2.85 bits
- Character sets: lowercase, digits (2 sets)
- Patterns: none detected
- Length: 11 characters

**Scoring:**

- Base entropy: 2.85 × 2 = 5.7 points
- Character set bonus: 2 × 2 = 4 points
- Length bonus: 11 × 0.5 = 5.5 points
- Pattern penalty: 0 points
- **Entropy Score**: 5.7 + 4 + 5.5 = 15.2 → 15 points

**Dictionary Analysis:**

- Common password: -20 points
- **Dictionary Score**: 30 - 20 = 10 points

**Reuse Analysis:**

- No duplicates: 0 penalty
- **Reuse Score**: 30 points

**Total Score**: 15 + 10 + 30 = 55 points (Medium)

---

## Performance Considerations

### Time Complexity Analysis

| Component              | Time Complexity | Notes                        |
| ---------------------- | --------------- | ---------------------------- |
| Entropy Calculation    | O(n)            | n = password length          |
| Character Set Analysis | O(n)            | Single pass through password |
| Pattern Detection      | O(n)            | Linear scan for patterns     |
| Dictionary Checking    | O(n)            | Hash table lookups           |
| Reuse Detection        | O(1)            | Hash-based lookup            |
| **Total per Password** | **O(n)**        | Linear in password length    |

### Space Complexity Analysis

| Component              | Space Complexity | Notes                  |
| ---------------------- | ---------------- | ---------------------- |
| Entropy Calculation    | O(k)             | k = unique characters  |
| Character Set Analysis | O(1)             | Fixed character sets   |
| Pattern Detection      | O(1)             | Fixed pattern lists    |
| Dictionary Checking    | O(d)             | d = dictionary size    |
| Reuse Detection        | O(m)             | m = total passwords    |
| **Total**              | **O(m + d)**     | Linear in dataset size |

### Optimization Strategies

1. **Hash-Based Reuse Detection**: O(n) instead of O(n²)
2. **Precomputed Character Sets**: O(1) lookups
3. **Efficient Pattern Matching**: Single-pass algorithms
4. **Memory-Efficient Storage**: Hash tables for O(1) access

---

## Conclusion

The Password Strength Auditor uses a sophisticated, multi-layered approach to password analysis that combines:

1. **Information Theory**: Shannon entropy for randomness measurement
2. **Security Heuristics**: Pattern detection and dictionary analysis
3. **Performance Optimization**: Hash-based algorithms for scalability
4. **Practical Scoring**: Intuitive 0-100 scale with clear categories

This approach provides both theoretical rigor and practical security insights, making it suitable for enterprise-grade password auditing and security assessment.

The system successfully balances accuracy with performance, enabling analysis of large password datasets while providing detailed, actionable security recommendations.
