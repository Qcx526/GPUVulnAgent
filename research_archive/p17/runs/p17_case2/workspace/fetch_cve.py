import json, sys, urllib.request

URLS = [
    'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-65160',
]

out = {}
for u in URLS:
    try:
        req = urllib.request.Request(u, headers={'User-Agent': 'curl/8'})
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read().decode('utf-8', 'replace')
        out[u] = json.loads(body)
    except Exception as e:
        out[u] = {'ERROR': repr(e)}

with open('cve_65160_nvd.json', 'w', encoding='utf-8') as f:
    json.dump(out, f, ensure_ascii=False, indent=2)

for u, d in out.items():
    print('=== URL', u)
    if 'ERROR' in d:
        print('ERROR', d['ERROR'])
        continue
    for v in d.get('vulnerabilities', []):
        c = v['cve']
        print('id:', c.get('id'))
        print('published:', c.get('published'), 'lastModified:', c.get('lastModified'))
        print('status:', c.get('vulnStatus'))
        print('source:', c.get('sourceIdentifier'))
        for desc in c.get('descriptions', []):
            print('desc[%s]: %s' % (desc.get('lang'), desc.get('value')))
        for w in c.get('weaknesses', []):
            print('weakness:', w.get('source'), [ (dd.get('value'), dd.get('description')) for dd in w.get('description', []) ])
        for m in c.get('metrics', {}):
            print('metrics key:', m)
            for e in c.get('metrics')[m]:
                print('   ', json.dumps(e, ensure_ascii=False))
        for ref in c.get('references', []):
            print('ref:', ref.get('url'), ref.get('tags'))
        print('configurations:', json.dumps(c.get('configurations', []), ensure_ascii=False)[:2000])
