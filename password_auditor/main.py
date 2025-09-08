"""
Main CLI interface for the Password Strength Auditor.
"""

import argparse
import sys
import os
from pathlib import Path
from typing import List, Tuple

try:
    # Try relative imports first (when run as module)
    from .core.analyzer import PasswordAnalyzer
    from .utils.csv_handler import CSVHandler
    from .utils.validators import InputValidator
    from .reporting.report_generator import ReportGenerator
    from .reporting.visualizer import PasswordVisualizer
except ImportError:
    # Fall back to absolute imports (when run directly)
    from password_auditor.core.analyzer import PasswordAnalyzer
    from password_auditor.utils.csv_handler import CSVHandler
    from password_auditor.utils.validators import InputValidator
    from password_auditor.reporting.report_generator import ReportGenerator
    from password_auditor.reporting.visualizer import PasswordVisualizer


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="CLI-based Password Strength Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s passwords.csv
  %(prog)s passwords.csv --output results.json --format json
  %(prog)s passwords.csv --visualize --threshold 50
  %(prog)s passwords.csv --top-weak 10 --top-strong 5
  %(prog)s --create-sample sample.csv
        """
    )
    
    # Input file argument
    parser.add_argument(
        'input_file',
        nargs='?',
        help='CSV file containing username/password data'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        help='Output file path for results'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['json', 'csv', 'txt'],
        default='txt',
        help='Output format (default: txt)'
    )
    
    # Analysis options
    parser.add_argument(
        '--threshold', '-t',
        type=int,
        default=50,
        help='Score threshold for filtering results (0-100, default: 50)'
    )
    
    parser.add_argument(
        '--top-weak',
        type=int,
        help='Show top N weakest passwords'
    )
    
    parser.add_argument(
        '--top-strong',
        type=int,
        help='Show top N strongest passwords'
    )
    
    parser.add_argument(
        '--category',
        choices=['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'],
        help='Filter by strength category'
    )
    
    # Visualization options
    parser.add_argument(
        '--visualize', '-v',
        action='store_true',
        help='Generate visualization charts'
    )
    
    parser.add_argument(
        '--chart-output',
        help='Output directory for chart files (default: current directory)'
    )
    
    # Dictionary options
    parser.add_argument(
        '--dictionary',
        help='Path to custom dictionary file for common password detection'
    )
    
    # Utility options
    parser.add_argument(
        '--create-sample',
        help='Create a sample CSV file with test data'
    )
    
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Validate CSV format without running analysis'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress progress output'
    )
    
    parser.add_argument(
        '--verbose', '-V',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser


def validate_arguments(args: argparse.Namespace) -> List[str]:
    """Validate command line arguments."""
    errors = []
    
    # If creating sample, input file is not required
    if args.create_sample:
        is_valid, error = InputValidator.validate_output_path(args.create_sample)
        if not is_valid:
            errors.append(f"Invalid sample output path: {error}")
        return errors
    
    # Input file is required for analysis
    if not args.input_file:
        errors.append("Input CSV file is required")
        return errors
    
    # Validate input file
    is_valid, error = InputValidator.validate_file_path(args.input_file, ['.csv'])
    if not is_valid:
        errors.append(f"Invalid input file: {error}")
    
    # Validate output file if specified
    if args.output:
        is_valid, error = InputValidator.validate_output_path(args.output)
        if not is_valid:
            errors.append(f"Invalid output path: {error}")
    
    # Validate threshold
    is_valid, error = InputValidator.validate_score_threshold(args.threshold)
    if not is_valid:
        errors.append(f"Invalid threshold: {error}")
    
    # Validate limits
    if args.top_weak:
        is_valid, error = InputValidator.validate_limit(args.top_weak)
        if not is_valid:
            errors.append(f"Invalid top-weak limit: {error}")
    
    if args.top_strong:
        is_valid, error = InputValidator.validate_limit(args.top_strong)
        if not is_valid:
            errors.append(f"Invalid top-strong limit: {error}")
    
    # Validate dictionary file if specified
    if args.dictionary:
        is_valid, error = InputValidator.validate_file_path(args.dictionary, ['.txt'])
        if not is_valid:
            errors.append(f"Invalid dictionary file: {error}")
    
    return errors


def create_sample_file(output_path: str, num_samples: int = 30) -> None:
    """Create a sample CSV file."""
    csv_handler = CSVHandler()
    csv_handler.create_sample_csv(output_path, num_samples)
    print(f"Sample CSV file created: {output_path}")
    print(f"Contains {num_samples} sample username/password pairs")


def validate_csv_file(file_path: str) -> None:
    """Validate CSV file format."""
    csv_handler = CSVHandler()
    is_valid, errors = csv_handler.validate_csv_format(file_path)
    
    if is_valid:
        print(f"✓ CSV file format is valid: {file_path}")
    else:
        print(f"✗ CSV file format errors:")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)


def run_analysis(args: argparse.Namespace) -> None:
    """Run the password analysis."""
    if not args.quiet:
        print("Loading password data...")
    
    # Load password data
    csv_handler = CSVHandler()
    try:
        password_data = csv_handler.read_password_csv(args.input_file)
    except Exception as e:
        print(f"Error loading CSV file: {e}", file=sys.stderr)
        sys.exit(1)
    
    if not args.quiet:
        print(f"Loaded {len(password_data)} password entries")
        print("Running password analysis...")
    
    # Initialize analyzer
    analyzer = PasswordAnalyzer(args.dictionary)
    
    # Run analysis
    try:
        results = analyzer.analyze_passwords(password_data)
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        sys.exit(1)
    
    if not args.quiet:
        print("Analysis complete!")
    
    # Generate reports
    report_generator = ReportGenerator()
    
    # Console output
    if not args.output or args.format == 'txt':
        report_generator.print_summary(analyzer.get_summary_statistics())
        
        if args.top_weak:
            print(f"\n--- Top {args.top_weak} Weakest Passwords ---")
            weak_passwords = analyzer.get_top_weak_passwords(args.top_weak)
            report_generator.print_password_list(weak_passwords)
        
        if args.top_strong:
            print(f"\n--- Top {args.top_strong} Strongest Passwords ---")
            strong_passwords = analyzer.get_top_strong_passwords(args.top_strong)
            report_generator.print_password_list(strong_passwords)
        
        if args.category:
            print(f"\n--- Passwords in '{args.category}' Category ---")
            category_passwords = analyzer.get_passwords_by_category(args.category)
            report_generator.print_password_list(category_passwords)
        
        # Filter by threshold
        if args.threshold < 100:
            filtered_results = [r for r in results if r['total_score'] < args.threshold]
            if filtered_results:
                print(f"\n--- Passwords Below Threshold ({args.threshold}) ---")
                report_generator.print_password_list(filtered_results)
    
    # File output
    if args.output:
        if args.format == 'json':
            with open(args.output, 'w') as f:
                f.write(analyzer.export_results('json'))
        elif args.format == 'csv':
            csv_handler.write_results_csv(results, args.output)
        else:  # txt format
            with open(args.output, 'w') as f:
                f.write(report_generator.generate_text_report(results, analyzer.get_summary_statistics()))
        
        if not args.quiet:
            print(f"Results saved to: {args.output}")
    
    # Generate visualizations
    if args.visualize:
        if not args.quiet:
            print("Generating visualizations...")
        
        visualizer = PasswordVisualizer()
        chart_output_dir = args.chart_output or os.getcwd()
        
        try:
            visualizer.create_score_distribution_chart(results, chart_output_dir)
            visualizer.create_strength_category_chart(results, chart_output_dir)
            visualizer.create_score_breakdown_chart(results, chart_output_dir)
            
            if not args.quiet:
                print(f"Charts saved to: {chart_output_dir}")
        except Exception as e:
            print(f"Error generating visualizations: {e}", file=sys.stderr)


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Validate arguments
    errors = validate_arguments(args)
    if errors:
        for error in errors:
            print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Handle special commands
        if args.create_sample:
            create_sample_file(args.create_sample)
            return
        
        if args.validate:
            validate_csv_file(args.input_file)
            return
        
        # Run analysis
        run_analysis(args)
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
