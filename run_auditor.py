#!/usr/bin/env python3
"""
Password Strength Auditor Launcher
This script can be run directly to launch the password auditor.
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Import and run the main function
from password_auditor.main import main

if __name__ == '__main__':
    main()
