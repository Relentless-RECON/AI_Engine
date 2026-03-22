import unittest

from sentinelfuzz_engine.recon import extract_candidate_endpoints_from_js


class ReconTests(unittest.TestCase):
    def test_extracts_api_candidates_from_js(self) -> None:
        js = """
        const a = "/rest/products/search?q=apple";
        const b = "/api/users";
        const c = "https://example.com/static/app.css";
        const d = "/graphql";
        """
        results = extract_candidate_endpoints_from_js(js, "https://example.com")
        joined = " ".join(results)
        self.assertIn("/rest/products/search", joined)
        self.assertIn("/api/users", joined)
        self.assertIn("/graphql", joined)
        self.assertNotIn(".css", joined)


if __name__ == "__main__":
    unittest.main()

