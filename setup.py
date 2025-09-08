from setuptools import setup, find_packages

setup(
    name="password-auditor",
    version="1.0.0",
    description="CLI-based Password Strength Auditor",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "matplotlib>=3.7.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
    ],
    entry_points={
        "console_scripts": [
            "password-auditor=password_auditor.main:main",
        ],
    },
    python_requires=">=3.8",
)
