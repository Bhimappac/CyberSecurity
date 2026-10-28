# pwaudit — Password-Policy Compliance Checker (Task 13)

Defensive, offline Python tool that audits **synthetic** credentials against a
NIST SP 800-63B-inspired policy. Standard library only (Python 3.8+).

## Usage
    python3 pwaudit.py data/synthetic_users.csv          # table report
    python3 pwaudit.py data/synthetic_users.csv --json   # machine-readable
    python3 -m unittest -v tests.test_pwaudit            # 14 test cases

Exit code is 0 if all accounts comply, 1 otherwise (CI-friendly).

## Rules checked
min length (12) | upper | lower | digit | symbol | common-password blocklist |
contains username | keyboard/alphanumeric sequence | repeated-character run |
reuse across accounts.

## Safety
Only synthetic data is used. Passwords are masked in all output.
