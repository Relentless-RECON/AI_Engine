import unittest

from sentinelfuzz_engine.payloads import build_payloads, sql_boolean_payload_pair


class PayloadTests(unittest.TestCase):
    def test_boolean_pair_templates(self) -> None:
        true_template, false_template = sql_boolean_payload_pair()
        self.assertIn("AND 1=1", true_template)
        self.assertIn("AND 1=2", false_template)

    def test_round_robin_keeps_xss_in_small_caps(self) -> None:
        payloads = build_payloads("NewsAd", 8)
        joined = " ".join(payloads).lower()
        self.assertTrue("script" in joined or "javascript:" in joined or "onerror" in joined)


if __name__ == "__main__":
    unittest.main()

