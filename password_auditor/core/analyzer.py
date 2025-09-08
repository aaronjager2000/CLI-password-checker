"""
Main password analyzer that orchestrates all analysis components.
"""

from typing import Dict, List, Tuple, Optional
from .entropy import EntropyCalculator
from .dictionary import DictionaryChecker
from .reuse_detector import ReuseDetector


class PasswordAnalyzer:
    """Main analyzer that combines all password analysis components."""
    
    def __init__(self, dictionary_file: str = None):
        """
        Initialize the password analyzer.
        
        Args:
            dictionary_file: Path to dictionary file (optional)
        """
        self.entropy_calculator = EntropyCalculator()
        self.dictionary_checker = DictionaryChecker(dictionary_file)
        self.reuse_detector = ReuseDetector()
        self.analysis_results = []
    
    def analyze_password(self, username: str, password: str) -> Dict:
        """
        Perform comprehensive analysis on a single password.
        
        Args:
            username: The username associated with the password
            password: The password to analyze
            
        Returns:
            Dictionary containing all analysis results
        """
        # Add password to reuse detector
        self.reuse_detector.add_password(username, password)
        
        # Calculate entropy score
        entropy_bits, entropy_score = self.entropy_calculator.calculate_entropy_score(password)
        entropy_analysis = {
            'entropy_bits': entropy_bits,
            'score': entropy_score,
            'character_sets': self.entropy_calculator.analyze_character_sets(password),
            'patterns': self.entropy_calculator.detect_patterns(password)
        }
        
        # Calculate dictionary score
        dict_score, dict_analysis = self.dictionary_checker.calculate_dictionary_score(password, username)
        
        # Calculate reuse score (will be 30 initially, updated after all passwords are processed)
        reuse_score, reuse_analysis = self.reuse_detector.calculate_reuse_score(username, password)
        
        # Calculate total score
        total_score = entropy_score + dict_score + reuse_score
        
        # Determine strength category
        strength_category = self._categorize_strength(total_score)
        
        analysis_result = {
            'username': username,
            'password': password,
            'total_score': total_score,
            'strength_category': strength_category,
            'entropy': entropy_analysis,
            'dictionary': dict_analysis,
            'reuse': reuse_analysis,
            'scores': {
                'entropy': entropy_score,
                'dictionary': dict_score,
                'reuse': reuse_score
            }
        }
        
        self.analysis_results.append(analysis_result)
        return analysis_result
    
    def analyze_passwords(self, password_data: List[Tuple[str, str]]) -> List[Dict]:
        """
        Analyze multiple passwords.
        
        Args:
            password_data: List of (username, password) tuples
            
        Returns:
            List of analysis results
        """
        results = []
        
        # First pass: analyze all passwords and add to reuse detector
        for username, password in password_data:
            result = self.analyze_password(username, password)
            results.append(result)
        
        # Second pass: recalculate reuse scores now that all passwords are known
        for i, (username, password) in enumerate(password_data):
            reuse_score, reuse_analysis = self.reuse_detector.calculate_reuse_score(username, password)
            
            # Update the result
            results[i]['reuse'] = reuse_analysis
            results[i]['scores']['reuse'] = reuse_score
            results[i]['total_score'] = (
                results[i]['scores']['entropy'] + 
                results[i]['scores']['dictionary'] + 
                reuse_score
            )
            results[i]['strength_category'] = self._categorize_strength(results[i]['total_score'])
        
        # Sort by total score (weakest first)
        results.sort(key=lambda x: x['total_score'])
        
        return results
    
    def _categorize_strength(self, score: int) -> str:
        """
        Categorize password strength based on score.
        
        Args:
            score: Total security score (0-100)
            
        Returns:
            Strength category string
        """
        if score >= 80:
            return "Very Strong"
        elif score >= 60:
            return "Strong"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"
    
    def get_summary_statistics(self) -> Dict:
        """
        Get summary statistics for all analyzed passwords.
        
        Returns:
            Dictionary of summary statistics
        """
        if not self.analysis_results:
            return {}
        
        total_passwords = len(self.analysis_results)
        scores = [result['total_score'] for result in self.analysis_results]
        
        # Calculate statistics
        avg_score = sum(scores) / len(scores)
        min_score = min(scores)
        max_score = max(scores)
        
        # Count by strength category
        category_counts = {}
        for result in self.analysis_results:
            category = result['strength_category']
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Calculate score distribution
        score_ranges = {
            'Very Weak (0-19)': len([s for s in scores if 0 <= s <= 19]),
            'Weak (20-39)': len([s for s in scores if 20 <= s <= 39]),
            'Medium (40-59)': len([s for s in scores if 40 <= s <= 59]),
            'Strong (60-79)': len([s for s in scores if 60 <= s <= 79]),
            'Very Strong (80-100)': len([s for s in scores if 80 <= s <= 100])
        }
        
        return {
            'total_passwords': total_passwords,
            'average_score': round(avg_score, 2),
            'min_score': min_score,
            'max_score': max_score,
            'strength_distribution': category_counts,
            'score_distribution': score_ranges,
            'reuse_statistics': self.reuse_detector.get_reuse_statistics()
        }
    
    def get_top_weak_passwords(self, limit: int = 10) -> List[Dict]:
        """
        Get the weakest passwords.
        
        Args:
            limit: Maximum number of passwords to return
            
        Returns:
            List of weakest password analysis results
        """
        return self.analysis_results[:limit]
    
    def get_top_strong_passwords(self, limit: int = 10) -> List[Dict]:
        """
        Get the strongest passwords.
        
        Args:
            limit: Maximum number of passwords to return
            
        Returns:
            List of strongest password analysis results
        """
        return self.analysis_results[-limit:][::-1]  # Reverse to get strongest first
    
    def get_passwords_by_category(self, category: str) -> List[Dict]:
        """
        Get passwords by strength category.
        
        Args:
            category: Strength category to filter by
            
        Returns:
            List of passwords in the specified category
        """
        return [result for result in self.analysis_results 
                if result['strength_category'] == category]
    
    def export_results(self, format: str = 'json') -> str:
        """
        Export analysis results in specified format.
        
        Args:
            format: Export format ('json', 'csv')
            
        Returns:
            Exported data as string
        """
        if format.lower() == 'json':
            import json
            return json.dumps(self.analysis_results, indent=2)
        elif format.lower() == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            if self.analysis_results:
                fieldnames = ['username', 'password', 'total_score', 'strength_category',
                            'entropy_score', 'dictionary_score', 'reuse_score']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in self.analysis_results:
                    writer.writerow({
                        'username': result['username'],
                        'password': result['password'],
                        'total_score': result['total_score'],
                        'strength_category': result['strength_category'],
                        'entropy_score': result['scores']['entropy'],
                        'dictionary_score': result['scores']['dictionary'],
                        'reuse_score': result['scores']['reuse']
                    })
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")
