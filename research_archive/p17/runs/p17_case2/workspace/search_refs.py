import os, re, json

KEYS = ["nvJPEG", "nvjpeg", "division", "divide", "divisor", "zero", "CVE-2026-65160", "CWE-369", "affect", "component", "version", "API", "jpeg"]

files = [f for f in os.listdir('.') if f.lower().endswith(('.txt', '.html', '.json'))]
print("FILES:", sorted(files))

for f in sorted(files):
    try:
        raw = open(f, 'rb').read()
    except Exception as e:
        print("ERR", f, e); continue
    txt = raw.decode('utf-8', errors='ignore')
    # strip html tags for readability
    plain = re.sub(r'<script.*?</script>', ' ', txt, flags=re.S | re.I)
    plain = re.sub(r'<style.*?</style>', ' ', plain, flags=re.S | re.I)
    plain = re.sub(r'<[^>]+>', ' ', plain)
    plain = re.sub(r'&nbsp;', ' ', plain)
    plain = re.sub(r'\s+', ' ', plain)
    print("=" * 70)
    print(f"FILE {f}  bytes={len(raw)}  plain_len={len(plain)}")
    for k in KEYS:
        hits = [m.start() for m in re.finditer(re.escape(k), plain, flags=re.I)]
        if hits:
            print(f"  [{k}] x{len(hits)}")
            for h in hits[:3]:
                print("     ...", plain[max(0, h-160):h+220].strip(), "...")
