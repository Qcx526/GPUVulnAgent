import os, sys, glob, subprocess, json
out = {}
out['cwd'] = os.getcwd()
cudas = [r'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2',
         r'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.4',
         r'D:\cuda1341_extract',
         r'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.4']
for c in cudas:
    out[c] = {
        'exists': os.path.isdir(c),
        'top': sorted(os.listdir(c))[:40] if os.path.isdir(c) else None,
    }

# find nvjpeg headers and libs anywhere under those roots (bounded depth)
def walk_find(root, patterns, maxdepth=6):
    hits = []
    if not os.path.isdir(root):
        return hits
    root = os.path.abspath(root)
    base_depth = root.count(os.sep)
    for dp, dns, fns in os.walk(root):
        if dp.count(os.sep) - base_depth > maxdepth:
            dns[:] = []
            continue
        for f in fns:
            lf = f.lower()
            for p in patterns:
                if lf == p or fnmatch_ok(lf, p):
                    hits.append(os.path.join(dp, f))
    return hits

import fnmatch
def fnmatch_ok(name, pat):
    return fnmatch.fnmatch(name, pat)

pats = ['nvjpeg*.dll', 'nvjpeg*.lib', 'nvjpeg*.h', 'nvjpeg*.hpp', 'cudart64*.dll', 'libnvjpeg*']
out['nvjpeg_hits'] = {}
for c in cudas:
    out['nvjpeg_hits'][c] = walk_find(c, pats, maxdepth=7)[:60]

# python packages
mods = {}
for m in ['PIL', 'numpy', 'cv2', 'ctypes', 'turbojpeg', 'imageio', 'skimage']:
    try:
        mod = __import__(m)
        mods[m] = getattr(mod, '__version__', 'present')
    except Exception as e:
        mods[m] = 'MISSING: %s' % e
out['python'] = mods
out['python_exe'] = sys.executable
out['path_env'] = os.environ.get('PATH', '')[:400]
print(json.dumps(out, indent=1, ensure_ascii=False))
