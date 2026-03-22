import json,collections 
d=json.load(open('engine_scan_juiceshop_improved.json','r',encoding='utf-8')) 
print('scan_id',d.get('scan_id')) 
print('target',d.get('target_url')) 
print('duration_ms',d.get('duration_ms')) 
print('stats',d.get('stats')) 
c=collections.Counter(f['vulnerability_type'] for f in d.get('findings',[])) 
s=collections.Counter(f['severity'] for f in d.get('findings',[])) 
print('types',dict(c)) 
print('severities',dict(s)) 
print('errors',d.get('errors',[])[:10]) 
print('first_endpoints_from_findings') 
for f in d.get('findings',[])[:10]: 
    print(f['vulnerability_type'],f['url']) 
