import time
import unittest

from sentinelfuzz_engine.job_manager import ScanJobManager


class JobManagerTests(unittest.TestCase):
    def test_job_completes_and_stores_result(self) -> None:
        def fake_runner(payload):
            time.sleep(0.05)
            return {
                "scan_id": "test-scan",
                "target_url": payload["target_url"],
                "stats": {"findings_count": 1, "requests_sent": 5},
                "findings": [],
                "errors": [],
            }

        manager = ScanJobManager(runner=fake_runner)
        job = manager.start_scan(
            {"target_url": "http://example.com", "authorized": True}
        )

        for _ in range(30):
            current = manager.get_job(job["job_id"])
            if current and current["status"] == "completed":
                break
            time.sleep(0.02)

        completed = manager.get_job(job["job_id"])
        self.assertIsNotNone(completed)
        self.assertEqual(completed["status"], "completed")
        result = manager.get_result(job["job_id"])
        self.assertIsNotNone(result)
        self.assertEqual(result["scan_id"], "test-scan")

    def test_payload_validation(self) -> None:
        manager = ScanJobManager(runner=lambda _: {})
        with self.assertRaises(PermissionError):
            manager.start_scan({"target_url": "http://example.com", "authorized": False})


if __name__ == "__main__":
    unittest.main()

