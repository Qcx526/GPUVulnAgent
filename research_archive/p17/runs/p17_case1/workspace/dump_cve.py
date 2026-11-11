import json, re, urllib.request

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

def get(u, timeout=60):
    req = urllib.request.Request(u, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode('utf-8', 'replace')

d = json.loads(get('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-65160'))
open('nvd_CVE-2026-65160.json', 'w', encoding='utf-8').write(json.dumps(d, indent=2, ensure_ascii=False))
cve = d['vulnerabilities'][0]['cve']

lines = []
lines.append('id: ' + cve['id'])
lines.append('published: %s  lastModified: %s' % (cve['published'], cve['lastModified']))
lines.append('status: ' + cve.get('vulnStatus', ''))
for desc in cve.get('descriptions', []):
    lines.append('desc[%s]: %s' % (desc['lang'], desc['value']))
for w in cve.get('weaknesses', []):
    for dd in w.get('description', []):
        lines.append('weakness: %s %s' % (w.get('source'), dd.get('value')))
for key, arr in cve.get('metrics', {}).items():
    for m in arr:
        cd = m.get('cvssData', {})
        lines.append('metric %s type=%s src=%s score=%s vector=%s' % (key, m.get('type'), m.get('source'), cd.get('baseScore'), cd.get('vectorString')))
for cfg in cve.get('configurations', []):
    lines.append('configurations: ' + json.dumps(cfg)[:2000])
refs = [r['url'] for r in cve.get('references', [])]
lines.append('references: %d' % len(refs))
for r in refs:
    lines.append('  ' + r)
report = '\n'.join(lines)
open('cve_report.txt', 'w', encoding='utf-8').write(report)
print(report)

for i, u in enumerate(refs):
    try:
        body = get(u)
        open('ref_%d.html' % i, 'w', encoding='utf-8').write(body)
        t = re.sub(r'<script.*?</script>', ' ', body, flags=re.S | re.I)
        t = re.sub(r'<style.*?</style>', ' ', t, flags=re.S | re.I)
        t = re.sub(r'<[^>]+>', ' ', t)
        t = t.replace('&nbsp;', ' ').replace('&amp;', '&')
        t = re.sub(r'[ \t\r]+', ' ', t)
        t = re.sub(r'\n\s*\n+', '\n', t)
        open('ref_%d.txt' % i, 'w', encoding='utf-8').write(u + '\n' + t)
        print('FETCHED %s bytes=%d text=%d' % (u, len(body), len(t)))
    except Exception as e:
        print('FAIL %s %r' % (u, e))
