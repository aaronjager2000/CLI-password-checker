# Password Strength Auditor

A comprehensive CLI-based tool for analyzing password strength from CSV files. This tool evaluates passwords using entropy calculations, dictionary checks, and reuse detection to provide detailed security assessments.

## 🚀 Features

- **Entropy Analysis**: Calculates Shannon entropy and character set diversity
- **Dictionary Checking**: Detects common passwords, dictionary words, and patterns
- **Reuse Detection**: Identifies duplicate and similar passwords across users
- **Comprehensive Scoring**: 0-100 scale with detailed breakdowns
- **Visual Reports**: Matplotlib-based charts and graphs
- **Multiple Output Formats**: JSON, CSV, and text reports
- **CLI Interface**: Easy-to-use command-line interface with argparse

## 📊 Scoring System

The tool uses a three-component scoring system (0-100 total):

- **Entropy Score (0-40 points)**: Based on character diversity, length, and pattern detection
- **Dictionary Score (0-30 points)**: Penalties for common words, patterns, and personal info
- **Reuse Score (0-30 points)**: Penalties for duplicate and similar passwords

### Strength Categories:

- **Very Weak (0-19)**: Critical security risk
- **Weak (20-39)**: High security risk
- **Medium (40-59)**: Moderate security risk
- **Strong (60-79)**: Good security
- **Very Strong (80-100)**: Excellent security

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Install the Package

```bash
pip install -e .
```

## 📁 Project Structure

```
CLI/
├── password_auditor/
│   ├── __init__.py
│   ├── main.py                 # CLI entry point
│   ├── core/
│   │   ├── entropy.py          # Entropy calculations
│   │   ├── dictionary.py       # Dictionary word detection
│   │   ├── reuse_detector.py   # Password reuse analysis
│   │   └── analyzer.py         # Main analysis orchestrator
│   ├── utils/
│   │   ├── csv_handler.py      # CSV input/output handling
│   │   ├── hashing.py          # Hashing utilities
│   │   └── validators.py       # Input validation
│   ├── reporting/
│   │   ├── report_generator.py # Text report generation
│   │   └── visualizer.py       # Matplotlib visualizations
│   └── data/
│       ├── common_passwords.txt # Dictionary file
│       └── sample_data.csv     # Example CSV
├── tests/
│   ├── test_entropy.py
│   ├── test_dictionary.py
│   └── test_integration.py
├── requirements.txt
├── setup.py
└── README.md
```

## 📋 Usage

### Basic Usage

**Option 1: Using the launcher script (Recommended)**

```bash
# Analyze passwords from CSV file
python run_auditor.py passwords.csv

# Create sample data for testing
python run_auditor.py --create-sample sample.csv

# Validate CSV format
python run_auditor.py --validate passwords.csv
```

**Option 2: Using Python module syntax**

```bash
# Analyze passwords from CSV file
python -m password_auditor.main passwords.csv

# Create sample data for testing
python -m password_auditor.main --create-sample sample.csv

# Validate CSV format
python -m password_auditor.main --validate passwords.csv
```

**Option 3: After installing the package**

```bash
# Install the package first
pip install -e .

# Then use the command-line tool
password-auditor passwords.csv
```

### Advanced Usage

```bash
# Generate JSON report with visualizations
python run_auditor.py passwords.csv --output results.json --format json --visualize

# Show only weak passwords (score < 50)
python run_auditor.py passwords.csv --threshold 50

# Show top 10 weakest and strongest passwords
python run_auditor.py passwords.csv --top-weak 10 --top-strong 10

# Filter by strength category
python run_auditor.py passwords.csv --category "Very Weak"

# Use custom dictionary file
python run_auditor.py passwords.csv --dictionary custom_dict.txt

# Generate charts in specific directory
python run_auditor.py passwords.csv --visualize --chart-output ./charts/
```

### Command Line Options

| Option            | Description                                        |
| ----------------- | -------------------------------------------------- |
| `input_file`      | CSV file containing username/password data         |
| `--output, -o`    | Output file path for results                       |
| `--format, -f`    | Output format: json, csv, txt (default: txt)       |
| `--threshold, -t` | Score threshold for filtering (0-100, default: 50) |
| `--top-weak`      | Show top N weakest passwords                       |
| `--top-strong`    | Show top N strongest passwords                     |
| `--category`      | Filter by strength category                        |
| `--visualize, -v` | Generate visualization charts                      |
| `--chart-output`  | Output directory for chart files                   |
| `--dictionary`    | Path to custom dictionary file                     |
| `--create-sample` | Create a sample CSV file with test data            |
| `--validate`      | Validate CSV format without running analysis       |
| `--quiet, -q`     | Suppress progress output                           |
| `--verbose, -V`   | Enable verbose output                              |

## 📄 CSV Format

The input CSV file should have the following format:

```csv
username,password,notes
john_doe,password123,Common weak password
jane_smith,MyStrongPass2023!,Strong password example
admin_user,admin,Very common password
```

**Required columns:**

- `username`: The username associated with the password
- `password`: The password to analyze

**Optional columns:**

- `notes`: Additional information about the password
- `email`: Email address (not used in analysis)
- `domain`: Domain information (not used in analysis)

## 📊 Output Examples

### Console Output

```
============================================================
PASSWORD STRENGTH AUDIT SUMMARY
============================================================
Total Passwords Analyzed: 25
Average Security Score: 45.2/100
Score Range: 5 - 95

Strength Distribution:
  🔴 Very Weak: 8 (32.0%)
  🟠 Weak: 7 (28.0%)
  🟡 Medium: 5 (20.0%)
  🟢 Strong: 3 (12.0%)
  🔵 Very Strong: 2 (8.0%)

--- Top 5 Weakest Passwords ---
 1. 🔴 admin_user           Score:  5/100 (Very Weak)
 2. 🔴 test_user            Score:  8/100 (Very Weak)
 3. 🔴 john_doe             Score: 12/100 (Very Weak)
 4. 🔴 jane_smith           Score: 15/100 (Very Weak)
 5. 🔴 demo_user            Score: 18/100 (Very Weak)
```

### Visualization Charts

The tool generates several charts when using the `--visualize` option:

- Score distribution histogram
- Strength category pie chart
- Score breakdown by component
- Password reuse analysis
- Trend analysis
- Comprehensive dashboard

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_entropy.py

# Run with verbose output
python -m pytest tests/ -v
```

## 🔧 Development

### Adding New Analysis Components

1. Create a new module in `password_auditor/core/`
2. Implement the analysis logic
3. Add the component to `PasswordAnalyzer` in `analyzer.py`
4. Update the scoring system
5. Add tests in `tests/`

### Extending Visualization

1. Add new chart methods to `PasswordVisualizer` in `reporting/visualizer.py`
2. Update the CLI to include new visualization options
3. Add the new charts to the comprehensive dashboard

## 📈 Performance Considerations

- **Large datasets**: The tool can handle up to 10,000 passwords efficiently
- **Memory usage**: Approximately 1MB per 1,000 passwords
- **Processing time**: ~0.1 seconds per password on modern hardware
- **Visualization**: Charts are generated only when requested

## 🔒 Security Considerations

- **Password handling**: Passwords are processed in memory and not logged
- **Hashing**: SHA-256 is used for password comparison
- **Data privacy**: No passwords are stored permanently
- **File permissions**: Ensure CSV files have appropriate permissions

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Troubleshooting

### Common Issues

**CSV format errors:**

```bash
# Validate your CSV file
python -m password_auditor.main --validate passwords.csv
```

**Missing dependencies:**

```bash
# Reinstall requirements
pip install -r requirements.txt
```

**Visualization errors:**

```bash
# Install matplotlib backend
pip install matplotlib[all]
```

**Memory issues with large files:**

- Split large CSV files into smaller chunks
- Use the `--quiet` option to reduce memory usage
- Process files in batches

### Getting Help

- Check the test files for usage examples
- Review the sample data in `password_auditor/data/`
- Run with `--verbose` for detailed error information

## 🎯 Future Enhancements

- [ ] Database integration for large-scale analysis
- [ ] Real-time password monitoring
- [ ] Integration with password managers
- [ ] Advanced pattern recognition
- [ ] Machine learning-based scoring
- [ ] Web interface
- [ ] API endpoints
- [ ] Multi-language support
