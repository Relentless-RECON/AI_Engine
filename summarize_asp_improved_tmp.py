import json,collections 
d=json.load(open('engine_scan_testaspnet_improved.json','r',encoding='utf-8')) 
print('scan_id',d.get('scan_id')) 
print('stats',d.get('stats')) 
c=collections.Counter(f['vulnerability_type'] for f in d.get('findings',[])) 
s=collections.Counter(f['severity'] for f in d.get('findings',[])) 
print('types',dict(c)) 
print('severities',dict(s)) 
print('sample') 
for f in d.get('findings',[])[:20]: 
    print(f['vulnerability_type'],f['parameter'],f['severity'],f['score']) 
