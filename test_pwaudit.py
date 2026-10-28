import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pwaudit import check, audit, summarize, has_sequence, longest_run, mask

class T(unittest.TestCase):
    def test_strong_passes(self):            self.assertEqual(check("alice", "T7#vq9Lm!Xr2pZ"), [])
    def test_short(self):                    self.assertIn("too_short", check("u", "Sh0rt!1"))
    def test_common(self):                   self.assertIn("common_password", check("u", "Password"))
    def test_common_case_insensitive(self):  self.assertIn("common_password", check("u", "WELCOME1"))
    def test_username(self):                 self.assertIn("contains_username", check("carol", "Carol@2024Secure"))
    def test_sequence(self):                 self.assertIn("sequential_pattern", check("u", "abcd1234EFGH#x"))
    def test_reverse_sequence(self):         self.assertTrue(has_sequence("xx4321xx"))
    def test_repeat(self):                   self.assertIn("repeated_characters", check("u", "aaaa1111BBBB!!"))
    def test_run_length(self):               self.assertEqual(longest_run("aabbbc"), 3)
    def test_no_symbol(self):                self.assertIn("no_symbol", check("u", "Abcdefgh12345x9"))
    def test_empty(self):                    self.assertIn("too_short", check("u", ""))
    def test_mask_hides_middle(self):        self.assertEqual(mask("abcdef"), "a****f")
    def test_reuse_detected(self):
        rows = [{"username":"a","password":"Tr33$Hill!Gr33n9"},{"username":"b","password":"Tr33$Hill!Gr33n9"}]
        self.assertTrue(all("reused_across_accounts" in r["violations"] for r in audit(rows)))
    def test_summary_rate(self):
        rows = [{"username":"a","password":"T7#vq9Lm!Xr2pZ"},{"username":"b","password":"password"}]
        s = summarize(audit(rows)); self.assertEqual((s["total"], s["compliant"], s["compliance_rate_pct"]), (2,1,50.0))
if __name__ == "__main__": unittest.main()
