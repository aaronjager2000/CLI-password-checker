"""
Report generation module for password analysis results.
"""

from typing import List, Dict
import json


class ReportGenerator:
    """Generates various types of reports from password analysis results."""
    
    def __init__(self):
        self.strength_colors = {
            'Very Weak': '🔴',
            'Weak': '🟠',
            'Medium': '🟡',
            'Strong': '🟢',
            'Very Strong': '🔵'
        }
    
    def print_summary(self, statistics: Dict) -> None:
        """Print summary statistics to console."""
        print("\n" + "="*60)
        print("PASSWORD STRENGTH AUDIT SUMMARY")
        print("="*60)
        
        print(f"Total Passwords Analyzed: {statistics['total_passwords']}")
        print(f"Average Security Score: {statistics['average_score']}/100")
        print(f"Score Range: {statistics['min_score']} - {statistics['max_score']}")
        
        print("\nStrength Distribution:")
        for category, count in statistics['strength_distribution'].items():
            percentage = (count / statistics['total_passwords']) * 100
            emoji = self.strength_colors.get(category, '⚪')
            print(f"  {emoji} {category}: {count} ({percentage:.1f}%)")
        
        print("\nScore Distribution:")
        for range_name, count in statistics['score_distribution'].items():
            percentage = (count / statistics['total_passwords']) * 100
            print(f"  {range_name}: {count} ({percentage:.1f}%)")
        
        # Reuse statistics
        reuse_stats = statistics.get('reuse_statistics', {})
        if reuse_stats:
            print("\nReuse Analysis:")
            print(f"  Unique Passwords: {reuse_stats['unique_passwords']}")
            print(f"  Duplicate Passwords: {reuse_stats['duplicate_passwords']}")
            print(f"  Users with Reuse: {reuse_stats['users_with_reuse']}")
            print(f"  Similar Password Groups: {reuse_stats['similar_groups']}")
            
            if reuse_stats['common_patterns']:
                print("  Common Patterns:")
                for pattern, count in reuse_stats['common_patterns'].items():
                    print(f"    {pattern}: {count}")
        
        print("="*60)
    
    def print_password_list(self, passwords: List[Dict], show_details: bool = False) -> None:
        """Print a list of passwords with their analysis."""
        if not passwords:
            print("No passwords found.")
            return
        
        print(f"\nFound {len(passwords)} passwords:")
        print("-" * 80)
        
        for i, result in enumerate(passwords, 1):
            emoji = self.strength_colors.get(result['strength_category'], '⚪')
            print(f"{i:2d}. {emoji} {result['username']:<20} "
                  f"Score: {result['total_score']:2d}/100 "
                  f"({result['strength_category']})")
            
            if show_details:
                print(f"     Password: {result['password']}")
                print(f"     Entropy: {result['scores']['entropy']}/40, "
                      f"Dictionary: {result['scores']['dictionary']}/30, "
                      f"Reuse: {result['scores']['reuse']}/30")
                
                # Show issues
                issues = []
                if result['dictionary']['common_passwords']:
                    issues.append("Common password")
                if result['dictionary']['dictionary_words']:
                    issues.append(f"Contains words: {', '.join(result['dictionary']['dictionary_words'])}")
                if result['dictionary']['keyboard_patterns']:
                    issues.append(f"Keyboard pattern: {', '.join(result['dictionary']['keyboard_patterns'])}")
                if result['reuse']['exact_duplicates'] > 0:
                    issues.append(f"Exact duplicate ({result['reuse']['exact_duplicates']} copies)")
                
                if issues:
                    print(f"     Issues: {'; '.join(issues)}")
                print()
    
    def generate_text_report(self, results: List[Dict], statistics: Dict) -> str:
        """Generate a comprehensive text report."""
        report = []
        report.append("PASSWORD STRENGTH AUDIT REPORT")
        report.append("=" * 50)
        report.append("")
        
        # Summary section
        report.append("SUMMARY")
        report.append("-" * 20)
        report.append(f"Total Passwords: {statistics['total_passwords']}")
        report.append(f"Average Score: {statistics['average_score']}/100")
        report.append(f"Score Range: {statistics['min_score']} - {statistics['max_score']}")
        report.append("")
        
        # Strength distribution
        report.append("STRENGTH DISTRIBUTION")
        report.append("-" * 25)
        for category, count in statistics['strength_distribution'].items():
            percentage = (count / statistics['total_passwords']) * 100
            report.append(f"{category}: {count} ({percentage:.1f}%)")
        report.append("")
        
        # Detailed results
        report.append("DETAILED RESULTS")
        report.append("-" * 20)
        report.append("Rank | Username           | Score | Category    | Password")
        report.append("-" * 70)
        
        for i, result in enumerate(results, 1):
            username = result['username'][:18]
            score = result['total_score']
            category = result['strength_category'][:11]
            password = result['password'][:20] + "..." if len(result['password']) > 20 else result['password']
            
            report.append(f"{i:4d} | {username:<18} | {score:5d} | {category:<11} | {password}")
        
        report.append("")
        
        # Recommendations
        report.append("RECOMMENDATIONS")
        report.append("-" * 18)
        
        weak_count = statistics['strength_distribution'].get('Very Weak', 0) + statistics['strength_distribution'].get('Weak', 0)
        if weak_count > 0:
            report.append(f"• {weak_count} passwords are weak or very weak and should be changed immediately")
        
        reuse_stats = statistics.get('reuse_statistics', {})
        if reuse_stats.get('duplicate_passwords', 0) > 0:
            report.append(f"• {reuse_stats['duplicate_passwords']} passwords are duplicated across users")
        
        if reuse_stats.get('users_with_reuse', 0) > 0:
            report.append(f"• {reuse_stats['users_with_reuse']} users have password reuse issues")
        
        report.append("• Implement password policy requiring minimum 12 characters")
        report.append("• Require mix of uppercase, lowercase, numbers, and special characters")
        report.append("• Prohibit common dictionary words and patterns")
        report.append("• Implement password history to prevent reuse")
        
        return "\n".join(report)
    
    def generate_json_report(self, results: List[Dict], statistics: Dict) -> str:
        """Generate a JSON report."""
        report_data = {
            'summary': statistics,
            'results': results,
            'metadata': {
                'total_analyzed': len(results),
                'generated_at': self._get_timestamp()
            }
        }
        return json.dumps(report_data, indent=2)
    
    def generate_security_recommendations(self, results: List[Dict], statistics: Dict) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # Analyze weak passwords
        weak_passwords = [r for r in results if r['total_score'] < 40]
        if weak_passwords:
            recommendations.append(f"CRITICAL: {len(weak_passwords)} passwords scored below 40/100")
            recommendations.append("These passwords should be changed immediately")
        
        # Analyze common issues
        common_passwords = sum(1 for r in results if r['dictionary']['common_passwords'])
        if common_passwords:
            recommendations.append(f"WARNING: {common_passwords} passwords are in common password lists")
        
        dictionary_words = sum(1 for r in results if r['dictionary']['dictionary_words'])
        if dictionary_words:
            recommendations.append(f"WARNING: {dictionary_words} passwords contain dictionary words")
        
        keyboard_patterns = sum(1 for r in results if r['dictionary']['keyboard_patterns'])
        if keyboard_patterns:
            recommendations.append(f"WARNING: {keyboard_patterns} passwords contain keyboard patterns")
        
        # Analyze reuse
        reuse_stats = statistics.get('reuse_statistics', {})
        if reuse_stats.get('duplicate_passwords', 0) > 0:
            recommendations.append(f"CRITICAL: {reuse_stats['duplicate_passwords']} passwords are duplicated")
        
        if reuse_stats.get('users_with_reuse', 0) > 0:
            recommendations.append(f"WARNING: {reuse_stats['users_with_reuse']} users have password reuse")
        
        # General recommendations
        recommendations.extend([
            "RECOMMENDATION: Implement minimum password length of 12 characters",
            "RECOMMENDATION: Require character set diversity (upper, lower, numbers, symbols)",
            "RECOMMENDATION: Prohibit common words and patterns",
            "RECOMMENDATION: Implement password history (prevent last 12 passwords)",
            "RECOMMENDATION: Consider implementing password managers for users"
        ])
        
        return recommendations
    
    def print_security_recommendations(self, results: List[Dict], statistics: Dict) -> None:
        """Print security recommendations to console."""
        recommendations = self.generate_security_recommendations(results, statistics)
        
        print("\n" + "="*60)
        print("SECURITY RECOMMENDATIONS")
        print("="*60)
        
        for recommendation in recommendations:
            print(f"• {recommendation}")
        
        print("="*60)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp as string."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def generate_executive_summary(self, statistics: Dict) -> str:
        """Generate an executive summary for management."""
        total = statistics['total_passwords']
        avg_score = statistics['average_score']
        
        # Calculate risk levels
        weak_count = (statistics['strength_distribution'].get('Very Weak', 0) + 
                     statistics['strength_distribution'].get('Weak', 0))
        medium_count = statistics['strength_distribution'].get('Medium', 0)
        strong_count = (statistics['strength_distribution'].get('Strong', 0) + 
                       statistics['strength_distribution'].get('Very Strong', 0))
        
        risk_level = "HIGH" if weak_count > total * 0.3 else "MEDIUM" if weak_count > total * 0.1 else "LOW"
        
        summary = f"""
EXECUTIVE SUMMARY - PASSWORD SECURITY AUDIT

OVERVIEW:
• {total} passwords analyzed
• Average security score: {avg_score}/100
• Overall risk level: {risk_level}

RISK BREAKDOWN:
• High Risk (Weak/Very Weak): {weak_count} passwords ({(weak_count/total)*100:.1f}%)
• Medium Risk: {medium_count} passwords ({(medium_count/total)*100:.1f}%)
• Low Risk (Strong/Very Strong): {strong_count} passwords ({(strong_count/total)*100:.1f}%)

KEY FINDINGS:
• {weak_count} passwords require immediate attention
• Average password strength is {'below' if avg_score < 50 else 'above'} acceptable threshold
• Password reuse detected across {statistics.get('reuse_statistics', {}).get('users_with_reuse', 0)} users

RECOMMENDED ACTIONS:
1. Immediate password changes for high-risk accounts
2. Implement stronger password policies
3. Deploy password management tools
4. Conduct security awareness training
"""
        return summary.strip()
