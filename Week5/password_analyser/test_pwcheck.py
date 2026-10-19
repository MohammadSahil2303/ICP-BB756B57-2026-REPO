import unittest, pwcheck as p
class T(unittest.TestCase):
    def test_common_is_very_weak(self):
        for pw in ["password", "123456", "P@ssw0rd", "Password123"]:
            self.assertLess(p.analyze(pw)["score"], 25, pw)
    def test_short_capped(self):
        self.assertLessEqual(p.analyze("aB3$x")["score"], 15)
    def test_ordering(self):
        a = p.analyze("hello")["score"]; b = p.analyze("Tr0ub4dor&3xK")["score"]; c = p.analyze("correct-Horse-battery-staple-92")["score"]
        self.assertLess(a, b); self.assertLessEqual(b, c + 20); self.assertGreaterEqual(c, 60)
    def test_patterns(self):
        self.assertTrue(p.find_patterns("qwerty99"))
        self.assertTrue(p.find_patterns("abcd5678"))
        self.assertTrue(p.find_patterns("aaa111"))
        self.assertTrue(any("year" in x for x in p.find_patterns("Summer2024!")))
    def test_entropy(self):
        self.assertAlmostEqual(p.entropy_bits("abcdefgh"), 8 * 4.7004, places=2)
        self.assertEqual(p.entropy_bits(""), 0)
        self.assertLess(p.shannon_bits("aaaaaaaa"), 1e-9)
    def test_policy_and_generator(self):
        self.assertTrue(all(p.policy_checks("Abcdef1234!x").values()))
        g = p.generate_passphrase(5); self.assertGreaterEqual(p.analyze(g)["score"], 50)
        self.assertNotEqual(g, p.generate_passphrase(5))
    def test_fmt(self):
        self.assertEqual(p.fmt_time(0.1), "instantly"); self.assertIn("years", p.fmt_time(1e9))
    def test_dictionary_model(self):
        # predictable "complex" passwords must not rate as strong
        for pw in ["Summer2024!", "Tr0ub4dor&3", "Welcome@123"]:
            self.assertLess(p.analyze(pw)["score"], 45, pw)
        self.assertGreaterEqual(p.analyze("Xk9#mQ2$vL7!pR")["score"], 60)
    def test_generator_entropy(self):
        self.assertEqual(p.generator_bits(5), round(5 * 11 + __import__("math").log2(5) + __import__("math").log2(100), 1))
    def test_empty(self):
        self.assertEqual(p.analyze("")["score"], 0)
if __name__ == "__main__": unittest.main()
