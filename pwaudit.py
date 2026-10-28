#!/usr/bin/env python3
"""pwaudit - password-policy compliance checker for SYNTHETIC account data.

Defensive, offline tool. Reads a CSV (username,password), evaluates every
record against a configurable policy modelled on NIST SP 800-63B guidance,
and prints a report. Passwords are never written to the output; only a
masked form is shown.
"""
import argparse, csv, json, re, sys
from collections import Counter

COMMON = {"password","password1","123456","12345678","123456789","qwerty","qwerty123",
          "letmein","welcome","welcome1","admin","admin123","iloveyou","abc123",
          "monkey","dragon","football","111111","passw0rd","changeme"}
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz","0123456789","qwertyuiop","asdfghjkl"]

DEFAULT_POLICY = {"min_length": 12, "require_upper": True, "require_lower": True,
                  "require_digit": True, "require_symbol": True,
                  "block_common": True, "block_username": True,
                  "block_sequences": True, "max_repeat_run": 3}

def has_sequence(pw, n=4):
    low = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - n + 1):
                if s[i:i+n] in low:
                    return True
    return False

def longest_run(pw):
    best = run = 1 if pw else 0
    for a, b in zip(pw, pw[1:]):
        run = run + 1 if a == b else 1
        best = max(best, run)
    return best

def check(username, pw, policy=DEFAULT_POLICY):
    """Return list of violated rule names for one credential."""
    v = []
    if len(pw) < policy["min_length"]: v.append("too_short")
    if policy["require_upper"] and not re.search(r"[A-Z]", pw): v.append("no_uppercase")
    if policy["require_lower"] and not re.search(r"[a-z]", pw): v.append("no_lowercase")
    if policy["require_digit"] and not re.search(r"\d", pw): v.append("no_digit")
    if policy["require_symbol"] and not re.search(r"[^A-Za-z0-9]", pw): v.append("no_symbol")
    if policy["block_common"] and pw.lower() in COMMON: v.append("common_password")
    if policy["block_username"] and username and username.lower() in pw.lower(): v.append("contains_username")
    if policy["block_sequences"] and has_sequence(pw): v.append("sequential_pattern")
    if longest_run(pw) > policy["max_repeat_run"]: v.append("repeated_characters")
    return v

def mask(pw):
    return pw[0] + "*" * (len(pw) - 2) + pw[-1] if len(pw) > 2 else "*" * len(pw)

def audit(rows, policy=DEFAULT_POLICY):
    results = []
    counts = Counter(r["password"] for r in rows)
    for r in rows:
        viol = check(r["username"], r["password"], policy)
        if counts[r["password"]] > 1: viol.append("reused_across_accounts")
        results.append({"username": r["username"], "masked": mask(r["password"]),
                        "compliant": not viol, "violations": viol})
    return results

def summarize(results):
    total = len(results); ok = sum(r["compliant"] for r in results)
    rules = Counter(v for r in results for v in r["violations"])
    return {"total": total, "compliant": ok, "non_compliant": total - ok,
            "compliance_rate_pct": round(100 * ok / total, 1) if total else 0.0,
            "violations_by_rule": dict(rules.most_common())}

def load(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv"); ap.add_argument("--json", action="store_true")
    ap.add_argument("--min-length", type=int, default=12)
    a = ap.parse_args(argv)
    policy = dict(DEFAULT_POLICY, min_length=a.min_length)
    res = audit(load(a.csv), policy); summ = summarize(res)
    if a.json:
        print(json.dumps({"summary": summ, "results": res}, indent=2)); return 0
    print(f"{'USER':<10} {'MASKED':<22} {'STATUS':<14} VIOLATIONS")
    for r in res:
        print(f"{r['username']:<10} {r['masked']:<22} {'PASS' if r['compliant'] else 'FAIL':<14} {', '.join(r['violations']) or '-'}")
    print("\nSUMMARY"); print(json.dumps(summ, indent=2))
    return 0 if summ["non_compliant"] == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
