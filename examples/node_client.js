/**
 * Node.js adapter example for SentinelFuzz core engine.
 * Works with Node 18+ (global fetch).
 */

const ENGINE_BASE = "http://127.0.0.1:8787";

async function startScan(targetUrl) {
  const response = await fetch(`${ENGINE_BASE}/v1/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target_url: targetUrl,
      authorized: true,
      max_depth: 2,
      max_pages: 30,
      max_payloads_per_param: 18,
      delay_ms: 100,
      include_header_scan: true,
      allow_private_targets: false,
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`failed to start scan (${response.status}): ${err}`);
  }

  const result = await response.json();
  return result.job;
}

async function getScanStatus(jobId) {
  const response = await fetch(`${ENGINE_BASE}/v1/scans/${jobId}`);
  if (!response.ok) {
    const err = await response.text();
    throw new Error(`status failed (${response.status}): ${err}`);
  }
  const data = await response.json();
  return data.job;
}

async function getScanResult(jobId) {
  const response = await fetch(`${ENGINE_BASE}/v1/scans/${jobId}/result`);
  if (response.status === 202) {
    return null;
  }
  if (!response.ok) {
    const err = await response.text();
    throw new Error(`result failed (${response.status}): ${err}`);
  }
  return response.json();
}

async function runScanAsync(targetUrl) {
  const job = await startScan(targetUrl);
  const jobId = job.job_id;

  // Poll until completion.
  for (;;) {
    const status = await getScanStatus(jobId);
    if (status.status === "completed") {
      const result = await getScanResult(jobId);
      if (!result) {
        throw new Error("job completed but result was empty");
      }
      return result;
    }
    if (status.status === "failed") {
      throw new Error(`scan failed: ${status.error || "unknown error"}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
}

async function main() {
  const target = process.argv[2] || "http://testphp.vulnweb.com";
  const scan = await runScanAsync(target);
  console.log(`Scan ID: ${scan.scan_id}`);
  console.log(`Findings: ${scan.stats.findings_count}`);
  for (const finding of scan.findings.slice(0, 5)) {
    console.log(
      `- [${finding.severity}] ${finding.vulnerability_type} param=${finding.parameter} score=${finding.score}`
    );
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
