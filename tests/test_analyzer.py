import unittest

from sentinelfuzz_engine.analyzer import analyze_boolean_sql, analyze_csrf_for_form, analyze_response
from sentinelfuzz_engine.types import Endpoint, HTTPResponse, RequestContext


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

    def test_detects_boolean_sql_differential(self) -> None:
        ctx = RequestContext(
            endpoint_url="http://example.com/news",
            method="GET",
            request_url="http://example.com/news?id=1",
            parameter="id",
            payload="1 AND 1=1 | 1 AND 1=2",
        )
        baseline = HTTPResponse(
            url=ctx.request_url,
            status=200,
            headers={},
            body="Welcome. Showing 10 records.",
            response_time_ms=110,
        )
        true_resp = HTTPResponse(
            url=ctx.request_url,
            status=200,
            headers={},
            body="Welcome. Showing 10 records.",
            response_time_ms=130,
        )
        false_resp = HTTPResponse(
            url=ctx.request_url,
            status=200,
            headers={},
            body="No records found for your query.",
            response_time_ms=120,
        )
        finding = analyze_boolean_sql(
            ctx=ctx, baseline=baseline, true_response=true_resp, false_response=false_resp
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.vulnerability_type, "sql_injection")

    def test_detects_missing_csrf_token(self) -> None:
        endpoint = Endpoint(
            url="http://example.com/login",
            method="POST",
            parameters=["username", "password"],
            source="form",
        )
        finding = analyze_csrf_for_form(endpoint)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.vulnerability_type, "csrf_missing_token")

    def test_detects_injection_anomaly_on_500(self) -> None:
        payload = "' OR '1'='1"
        ctx = RequestContext(
            endpoint_url="http://example.com/items",
            method="GET",
            request_url=f"http://example.com/items?id={payload}",
            parameter="id",
            payload=payload,
        )
        resp = HTTPResponse(
            url=ctx.request_url,
            status=500,
            headers={},
            body="Internal Server Error",
            response_time_ms=100,
        )
        findings = analyze_response(
            ctx=ctx, response=resp, baseline_ms=90, baseline_status=200
        )
        self.assertTrue(any(f.vulnerability_type == "injection_anomaly" for f in findings))


if __name__ == "__main__":
    unittest.main()
