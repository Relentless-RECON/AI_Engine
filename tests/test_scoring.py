import unittest

from sentinelfuzz_engine.scoring import calculate_score


class ScoringTests(unittest.TestCase):
    def test_sqli_scores_high(self) -> None:
        score, severity = calculate_score("sql_injection", 0.9)
        self.assertGreaterEqual(score, 7.0)
        self.assertIn(severity, {"High", "Critical"})

    def test_low_confidence_penalty(self) -> None:
        high_conf, _ = calculate_score("xss_reflected", 0.9)
        low_conf, _ = calculate_score("xss_reflected", 0.3)
        self.assertGreater(high_conf, low_conf)


if __name__ == "__main__":
    unittest.main()

