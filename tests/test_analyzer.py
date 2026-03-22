import unittest

from sentinelfuzz_engine.analyzer import analyze_response
from sentinelfuzz_engine.types import HTTPResponse, RequestContext


class AnalyzerTests(unittest.TestCase):
    def test_detects_sql_error_signature(self) -> None:
        ctx = RequestContext(
            endpoint_url="http://example.com/login",
            method="GET",
            request_url="http://example.com/login?id='",
            parameter="id",
            payload="'",
        )
        resp = HTTPResponse(
            url=ctx.request_url,
            status=500,
            headers={},
            body="You have an error in your SQL syntax near ...",
            response_time_ms=120,
        )
        findings = analyze_response(ctx=ctx, response=resp, baseline_ms=110)
        self.assertTrue(any(f.vulnerability_type == "sql_injection" for f in findings))

    def test_detects_reflected_xss(self) -> None:
        payload = "<script>alert(1)</script>"
        ctx = RequestContext(
            endpoint_url="http://example.com/search",
            method="GET",
            request_url=f"http://example.com/search?q={payload}",
            parameter="q",
            payload=payload,
        )
        resp = HTTPResponse(
            url=ctx.request_url,
            status=200,
            headers={},
            body=f"<html><body>{payload}</body></html>",
            response_time_ms=90,
        )
        findings = analyze_response(ctx=ctx, response=resp, baseline_ms=80)
        self.assertTrue(any(f.vulnerability_type == "xss_reflected" for f in findings))


if __name__ == "__main__":
    unittest.main()

