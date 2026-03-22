import json 
from sentinelfuzz_engine.types import ScanConfig 
from sentinelfuzz_engine.scanner import ScanEngine 
cfg = ScanConfig(target_url='http://testaspnet.vulnweb.com', authorized=True, max_depth=1, max_pages=10, max_payloads_per_param=8, delay_ms=10, include_header_scan=True, allow_private_targets=False, enable_spa_api_discovery=True, max_js_files=5, guess_common_params=True) 
result = ScanEngine(cfg).run().to_dict() 
with open('engine_scan_testaspnet_tuned.json','w',encoding='utf-8') as f: 
    json.dump(result,f,indent=2) 
print('scan_complete') 
print('findings', result['stats']['findings_count']) 
print('requests', result['stats']['requests_sent']) 
print('endpoints', result['stats']['endpoints_discovered']) 
print('errors', result['stats']['errors_count']) 
