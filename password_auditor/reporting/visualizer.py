"""
Visualization module for password analysis results using matplotlib.
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from typing import List, Dict
import os
from pathlib import Path


class PasswordVisualizer:
    """Creates visualizations for password analysis results."""
    
    def __init__(self):
        self.colors = {
            'Very Weak': '#FF4444',
            'Weak': '#FF8800', 
            'Medium': '#FFDD00',
            'Strong': '#88DD88',
            'Very Strong': '#4488FF'
        }
        
        # Set style
        plt.style.use('default')
        plt.rcParams['figure.figsize'] = (12, 8)
        plt.rcParams['font.size'] = 10
    
    def create_score_distribution_chart(self, results: List[Dict], output_dir: str) -> None:
        """Create a histogram showing score distribution."""
        scores = [result['total_score'] for result in results]
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        # Create histogram
        n, bins, patches = ax.hist(scores, bins=20, alpha=0.7, edgecolor='black')
        
        # Color bars based on score ranges
        for i, (patch, bin_left) in enumerate(zip(patches, bins[:-1])):
            if bin_left < 20:
                patch.set_facecolor(self.colors['Very Weak'])
            elif bin_left < 40:
                patch.set_facecolor(self.colors['Weak'])
            elif bin_left < 60:
                patch.set_facecolor(self.colors['Medium'])
            elif bin_left < 80:
                patch.set_facecolor(self.colors['Strong'])
            else:
                patch.set_facecolor(self.colors['Very Strong'])
        
        ax.set_xlabel('Security Score')
        ax.set_ylabel('Number of Passwords')
        ax.set_title('Password Security Score Distribution')
        ax.grid(True, alpha=0.3)
        
        # Add statistics text
        mean_score = np.mean(scores)
        median_score = np.median(scores)
        ax.axvline(mean_score, color='red', linestyle='--', alpha=0.7, label=f'Mean: {mean_score:.1f}')
        ax.axvline(median_score, color='blue', linestyle='--', alpha=0.7, label=f'Median: {median_score:.1f}')
        ax.legend()
        
        plt.tight_layout()
        
        # Save chart
        output_path = Path(output_dir) / 'score_distribution.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def create_strength_category_chart(self, results: List[Dict], output_dir: str) -> None:
        """Create a pie chart showing strength category distribution."""
        # Count passwords by category
        category_counts = {}
        for result in results:
            category = result['strength_category']
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Prepare data
        categories = list(category_counts.keys())
        counts = list(category_counts.values())
        colors = [self.colors.get(cat, '#CCCCCC') for cat in categories]
        
        # Create pie chart
        fig, ax = plt.subplots(figsize=(10, 8))
        
        wedges, texts, autotexts = ax.pie(
            counts, 
            labels=categories, 
            colors=colors,
            autopct='%1.1f%%',
            startangle=90,
            textprops={'fontsize': 12}
        )
        
        # Enhance text
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        
        ax.set_title('Password Strength Category Distribution', fontsize=16, fontweight='bold')
        
        # Add legend with counts
        legend_labels = [f'{cat}: {count} passwords' for cat, count in zip(categories, counts)]
        ax.legend(wedges, legend_labels, title="Categories", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
        
        plt.tight_layout()
        
        # Save chart
        output_path = Path(output_dir) / 'strength_categories.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def create_score_breakdown_chart(self, results: List[Dict], output_dir: str) -> None:
        """Create a stacked bar chart showing score breakdown by component."""
        # Prepare data
        entropy_scores = [result['scores']['entropy'] for result in results]
        dict_scores = [result['scores']['dictionary'] for result in results]
        reuse_scores = [result['scores']['reuse'] for result in results]
        total_scores = [result['total_score'] for result in results]
        
        # Sort by total score
        sorted_indices = sorted(range(len(results)), key=lambda i: total_scores[i])
        
        # Take top 20 for readability
        top_20_indices = sorted_indices[:20]
        
        usernames = [results[i]['username'][:15] for i in top_20_indices]
        entropy_top20 = [entropy_scores[i] for i in top_20_indices]
        dict_top20 = [dict_scores[i] for i in top_20_indices]
        reuse_top20 = [reuse_scores[i] for i in top_20_indices]
        
        # Create stacked bar chart
        fig, ax = plt.subplots(figsize=(14, 8))
        
        x = np.arange(len(usernames))
        width = 0.6
        
        p1 = ax.bar(x, entropy_top20, width, label='Entropy', color='#4CAF50', alpha=0.8)
        p2 = ax.bar(x, dict_top20, width, bottom=entropy_top20, label='Dictionary', color='#FF9800', alpha=0.8)
        p3 = ax.bar(x, reuse_top20, width, bottom=np.array(entropy_top20) + np.array(dict_top20), 
                   label='Reuse', color='#F44336', alpha=0.8)
        
        ax.set_xlabel('Users (Top 20 Weakest)')
        ax.set_ylabel('Security Score')
        ax.set_title('Password Security Score Breakdown by Component')
        ax.set_xticks(x)
        ax.set_xticklabels(usernames, rotation=45, ha='right')
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')
        
        # Add total score line
        total_top20 = [total_scores[i] for i in top_20_indices]
        ax2 = ax.twinx()
        ax2.plot(x, total_top20, 'ko-', linewidth=2, markersize=6, label='Total Score')
        ax2.set_ylabel('Total Score', color='black')
        ax2.tick_params(axis='y', labelcolor='black')
        
        plt.tight_layout()
        
        # Save chart
        output_path = Path(output_dir) / 'score_breakdown.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def create_reuse_analysis_chart(self, results: List[Dict], output_dir: str) -> None:
        """Create charts showing password reuse analysis."""
        # This would require access to the analyzer's reuse statistics
        # For now, create a placeholder
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Simulate reuse data (in real implementation, get from analyzer)
        reuse_types = ['Exact Duplicates', 'Similar Passwords', 'User Reuse', 'Common Patterns']
        reuse_counts = [5, 12, 8, 15]  # Example data
        
        # Bar chart for reuse types
        bars = ax1.bar(reuse_types, reuse_counts, color=['#FF4444', '#FF8800', '#FFDD00', '#88DD88'])
        ax1.set_title('Password Reuse Analysis')
        ax1.set_ylabel('Number of Issues')
        ax1.tick_params(axis='x', rotation=45)
        
        # Add value labels on bars
        for bar, count in zip(bars, reuse_counts):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                    str(count), ha='center', va='bottom')
        
        # Pie chart for reuse vs unique
        unique_count = len(results) - sum(reuse_counts)
        reuse_total = sum(reuse_counts)
        
        ax2.pie([unique_count, reuse_total], 
               labels=['Unique Passwords', 'Reused Passwords'],
               colors=['#4CAF50', '#F44336'],
               autopct='%1.1f%%',
               startangle=90)
        ax2.set_title('Unique vs Reused Passwords')
        
        plt.tight_layout()
        
        # Save chart
        output_path = Path(output_dir) / 'reuse_analysis.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def create_trend_analysis_chart(self, results: List[Dict], output_dir: str) -> None:
        """Create a chart showing password strength trends."""
        # Sort by score and create trend line
        sorted_results = sorted(results, key=lambda x: x['total_score'])
        scores = [result['total_score'] for result in sorted_results]
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        # Create trend line
        x = np.arange(len(scores))
        ax.plot(x, scores, 'b-', linewidth=2, alpha=0.7, label='Security Score Trend')
        
        # Add moving average
        window_size = max(1, len(scores) // 10)
        moving_avg = np.convolve(scores, np.ones(window_size)/window_size, mode='valid')
        ax.plot(x[window_size-1:], moving_avg, 'r--', linewidth=2, label=f'Moving Average ({window_size})')
        
        # Color background by strength zones
        ax.axhspan(0, 20, alpha=0.1, color='red', label='Very Weak Zone')
        ax.axhspan(20, 40, alpha=0.1, color='orange', label='Weak Zone')
        ax.axhspan(40, 60, alpha=0.1, color='yellow', label='Medium Zone')
        ax.axhspan(60, 80, alpha=0.1, color='lightgreen', label='Strong Zone')
        ax.axhspan(80, 100, alpha=0.1, color='lightblue', label='Very Strong Zone')
        
        ax.set_xlabel('Password Rank (Weakest to Strongest)')
        ax.set_ylabel('Security Score')
        ax.set_title('Password Security Score Trend Analysis')
        ax.grid(True, alpha=0.3)
        ax.legend()
        
        # Add statistics
        mean_score = np.mean(scores)
        ax.axhline(mean_score, color='green', linestyle=':', alpha=0.7, label=f'Mean: {mean_score:.1f}')
        
        plt.tight_layout()
        
        # Save chart
        output_path = Path(output_dir) / 'trend_analysis.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def create_comprehensive_dashboard(self, results: List[Dict], statistics: Dict, output_dir: str) -> None:
        """Create a comprehensive dashboard with multiple charts."""
        fig = plt.figure(figsize=(20, 12))
        
        # Create grid layout
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        # 1. Score distribution (top left)
        ax1 = fig.add_subplot(gs[0, 0])
        scores = [result['total_score'] for result in results]
        ax1.hist(scores, bins=15, alpha=0.7, color='skyblue', edgecolor='black')
        ax1.set_title('Score Distribution')
        ax1.set_xlabel('Security Score')
        ax1.set_ylabel('Count')
        ax1.grid(True, alpha=0.3)
        
        # 2. Strength categories (top center)
        ax2 = fig.add_subplot(gs[0, 1])
        category_counts = statistics['strength_distribution']
        categories = list(category_counts.keys())
        counts = list(category_counts.values())
        colors = [self.colors.get(cat, '#CCCCCC') for cat in categories]
        ax2.pie(counts, labels=categories, colors=colors, autopct='%1.1f%%')
        ax2.set_title('Strength Categories')
        
        # 3. Score ranges (top right)
        ax3 = fig.add_subplot(gs[0, 2])
        score_ranges = statistics['score_distribution']
        ranges = list(score_ranges.keys())
        range_counts = list(score_ranges.values())
        ax3.bar(range(len(ranges)), range_counts, color='lightcoral')
        ax3.set_title('Score Ranges')
        ax3.set_xticks(range(len(ranges)))
        ax3.set_xticklabels([r.split('(')[0].strip() for r in ranges], rotation=45)
        ax3.set_ylabel('Count')
        
        # 4. Top 10 weakest (middle left)
        ax4 = fig.add_subplot(gs[1, 0])
        weakest_10 = sorted(results, key=lambda x: x['total_score'])[:10]
        usernames = [r['username'][:10] for r in weakest_10]
        scores_weak = [r['total_score'] for r in weakest_10]
        bars = ax4.barh(usernames, scores_weak, color='red', alpha=0.7)
        ax4.set_title('Top 10 Weakest Passwords')
        ax4.set_xlabel('Security Score')
        
        # 5. Top 10 strongest (middle center)
        ax5 = fig.add_subplot(gs[1, 1])
        strongest_10 = sorted(results, key=lambda x: x['total_score'], reverse=True)[:10]
        usernames_strong = [r['username'][:10] for r in strongest_10]
        scores_strong = [r['total_score'] for r in strongest_10]
        bars = ax5.barh(usernames_strong, scores_strong, color='green', alpha=0.7)
        ax5.set_title('Top 10 Strongest Passwords')
        ax5.set_xlabel('Security Score')
        
        # 6. Component breakdown (middle right)
        ax6 = fig.add_subplot(gs[1, 2])
        entropy_avg = np.mean([r['scores']['entropy'] for r in results])
        dict_avg = np.mean([r['scores']['dictionary'] for r in results])
        reuse_avg = np.mean([r['scores']['reuse'] for r in results])
        
        components = ['Entropy', 'Dictionary', 'Reuse']
        avg_scores = [entropy_avg, dict_avg, reuse_avg]
        colors_comp = ['#4CAF50', '#FF9800', '#F44336']
        
        bars = ax6.bar(components, avg_scores, color=colors_comp, alpha=0.7)
        ax6.set_title('Average Component Scores')
        ax6.set_ylabel('Average Score')
        ax6.set_ylim(0, 40)
        
        # Add value labels
        for bar, score in zip(bars, avg_scores):
            ax6.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, 
                    f'{score:.1f}', ha='center', va='bottom')
        
        # 7. Summary statistics (bottom)
        ax7 = fig.add_subplot(gs[2, :])
        ax7.axis('off')
        
        # Create summary text
        summary_text = f"""
        PASSWORD SECURITY AUDIT SUMMARY
        Total Passwords: {statistics['total_passwords']} | 
        Average Score: {statistics['average_score']}/100 | 
        Score Range: {statistics['min_score']} - {statistics['max_score']} |
        Weak Passwords: {statistics['strength_distribution'].get('Very Weak', 0) + statistics['strength_distribution'].get('Weak', 0)} |
        Strong Passwords: {statistics['strength_distribution'].get('Strong', 0) + statistics['strength_distribution'].get('Very Strong', 0)}
        """
        
        ax7.text(0.5, 0.5, summary_text, ha='center', va='center', 
                fontsize=14, fontweight='bold', transform=ax7.transAxes)
        
        # Overall title
        fig.suptitle('Password Security Audit Dashboard', fontsize=20, fontweight='bold')
        
        # Save dashboard
        output_path = Path(output_dir) / 'password_audit_dashboard.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
