import ctypes, os, sys, json, glob, struct, hashlib, subprocess, traceback

WS = os.path.dirname(os.path.abspath(__file__))
MUT = os.path.join(WS, 'mutants')

NVJ = [
  ("11.2", r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2\bin\nvjpeg64_11.dll", r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2\bin"),
  ("12.4", r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.4\bin\nvjpeg64_12.dll", r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.4\bin"),
  ("13.4", r"D:\cuda1341_extract\libnvjpeg\nvjpeg\bin\x64\nvjpeg64_13.dll", r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.4\bin"),
]

ST = {0:'SUCCESS',1:'INVALID_PARAMETER',2:'INVALID_HANDLE',3:'DEVICE_ALLOCATOR_FAILURE',
      4:'ALLOCATOR_FAILURE',5:'IMPLEMENTATION_NOT_SUPPORTED',6:'EXECUTION_FAILED',7:'ARCH_MISMATCH',
      8:'INVALID_JPEG'}
CSS = {0:'444',1:'422',2:'420',3:'440',4:'411',5:'410',6:'GRAY',7:'410V',0xffff:'UNKNOWN'}

class NvjpegImage(ctypes.Structure):
    _fields_ = [('channel', ctypes.c_void_p*4), ('pitch', ctypes.c_size_t*4)]

def find_cudart(bindir):
    c = sorted(glob.glob(os.path.join(bindir, 'cudart64_*.dll')))
    return c[-1] if c else None

# ---------------- worker ----------------
def worker(dll, bindir, cudart, manifest_path):
    out = {'dll': dll, 'cudart': cudart, 'bindir': bindir}
    for d in (bindir, os.path.dirname(dll)):
        try: os.add_dll_directory(d)
        except Exception as e: out.setdefault('dll_dir_err', []).append([d, repr(e)])
    try:
        cuda = ctypes.CDLL(cudart)
    except Exception as e:
        out['cudart_load_error'] = repr(e); return out
    try:
        lib = ctypes.CDLL(dll)
    except Exception as e:
        out['dll_load_error'] = repr(e); return out
    out['load'] = 'ok'

    P = ctypes.POINTER
    lib.nvjpegCreateSimple.argtypes=[P(ctypes.c_void_p)]; lib.nvjpegCreateSimple.restype=ctypes.c_int
    lib.nvjpegDestroy.argtypes=[ctypes.c_void_p]
    lib.nvjpegGetProperty.argtypes=[ctypes.c_int, P(ctypes.c_size_t)]
    lib.nvjpegJpegStateCreate.argtypes=[ctypes.c_void_p, P(ctypes.c_void_p)]
    lib.nvjpegJpegStateDestroy.argtypes=[ctypes.c_void_p]
    lib.nvjpegGetImageInfo.argtypes=[ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, P(ctypes.c_int), P(ctypes.c_int), P(ctypes.c_int), P(ctypes.c_int)]
    lib.nvjpegDecode.argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int, P(NvjpegImage), ctypes.c_void_p]
    cuda.cudaMalloc.argtypes=[P(ctypes.c_void_p), ctypes.c_size_t]
    cuda.cudaFree.argtypes=[ctypes.c_void_p]
    cuda.cudaMemcpy.argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    cuda.cudaDeviceSynchronize.restype=ctypes.c_int
    cuda.cudaGetErrorString.argtypes=[ctypes.c_int]; cuda.cudaGetErrorString.restype=ctypes.c_char_p

    ver = {}
    for nm, idx in (('major',1),('minor',2),('patch',3)):
        v = ctypes.c_size_t(0); r = lib.nvjpegGetProperty(idx, ctypes.byref(v))
        ver[nm] = [r, v.value]
    out['version'] = ver

    h = ctypes.c_void_p()
    cr = lib.nvjpegCreateSimple(ctypes.byref(h))
    out['create'] = ST.get(cr, cr)
    if cr != 0:
        return out
    try:
        p1 = ctypes.c_int(0); p2 = ctypes.c_int(0)
        if hasattr(lib, 'nvjpegGetHardwareDecoderInfo'):
            lib.nvjpegGetHardwareDecoderInfo.argtypes=[ctypes.c_void_p, P(ctypes.c_int), P(ctypes.c_int)]
            r = lib.nvjpegGetHardwareDecoderInfo(h, ctypes.byref(p1), ctypes.byref(p2))
            out['hw_decoder'] = {'status': r, 'parallelism': p1.value, 'cores': p2.value}
    except Exception as e:
        out['hw_decoder'] = repr(e)

    items = json.load(open(manifest_path, 'r'))
    res = {}
    for it in items:
        name = it['name']
        try:
            data = open(it['path'], 'rb').read()
        except Exception as e:
            res[name] = {'read_error': repr(e)}; continue
        rec = {'bytes': len(data), 'sha': hashlib.sha256(data).hexdigest()[:12]}
        st_h = ctypes.c_void_p()
        cs = lib.nvjpegJpegStateCreate(h, ctypes.byref(st_h))
        rec['state'] = ST.get(cs, cs)
        ncomp = ctypes.c_int(0); css = (ctypes.c_int*4)(); ws = (ctypes.c_int*4)(); hs = (ctypes.c_int*4)()
        bs = ctypes.c_char_p(data)
        gi = lib.nvjpegGetImageInfo(h, bs, len(data), ctypes.byref(ncomp), css, ws, hs)
        rec['getinfo'] = ST.get(gi, gi)
        if gi == 0:
            rec['ncomp'] = ncomp.value
            rec['css'] = CSS.get(css[0], css[0])
            rec['dims'] = [ws[0], hs[0]]
        if gi == 0 and ws[0] > 0 and hs[0] > 0 and ncomp.value >= 1:
            if ncomp.value == 1:
                fmt, pitch, ch = 0, ws[0], 1
            else:
                fmt, pitch, ch = 4, ws[0]*3, 1
            nbytes = pitch*hs[0]
            rec['out_fmt'] = {0:'UNCHANGED(planar)', 4:'RGBI'}[fmt]
            img = NvjpegImage()
            for i in range(4):
                img.channel[i] = None; img.pitch[i] = 0
            dev = ctypes.c_void_p()
            e = cuda.cudaMalloc(ctypes.byref(dev), nbytes)
            rec['cudaMalloc'] = [e, cuda.cudaGetErrorString(e).decode() if e else 'ok', nbytes]
            if e == 0:
                img.channel[0] = dev; img.pitch[0] = pitch
                try:
                    d = lib.nvjpegDecode(h, st_h, bs, len(data), fmt, ctypes.byref(img), None)
                except Exception as ex:
                    d = -999; rec['decode_exc'] = repr(ex)
                rec['decode'] = ST.get(d, d)
                if d == 0:
                    host = (ctypes.c_ubyte*nbytes)()
                    me = cuda.cudaMemcpy(host, dev, nbytes, 2)
                    sy = cuda.cudaDeviceSynchronize()
                    rec['memcpy'] = [me, sy]
                    b = bytes(host)
                    rec['sha_out'] = hashlib.sha256(b).hexdigest()[:16]
                    rec['min'] = min(b); rec['max'] = max(b)
                    rec['mean'] = round(sum(b)/len(b), 2)
                    rec['distinct'] = len(set(b))
                cuda.cudaFree(dev)
        lib.nvjpegJpegStateDestroy(st_h)
        res[name] = rec
    out['results'] = res
    try: lib.nvjpegDestroy(h)
    except Exception: pass
    return out

# ---------------- jpeg parsing / mutation ----------------
def parse_jpeg(data):
    p = {'markers': [], 'sof': None, 'sos': None, 'eoi': None, 'dqt': [], 'dht': [], 'dri': None, 'app0': None}
    if data[:2] != b'\xff\xd8':
        p['err'] = 'no SOI'; return p
    i = 2
    while i < len(data)-1:
        if data[i] != 0xFF:
            p['err'] = 'expected marker at %d' % i; break
        m = data[i+1]
        if m == 0xD9:
            p['markers'].append(['EOI', i]); p['eoi'] = i; break
        if m == 0xD8 or m == 0x01 or 0xD0 <= m <= 0xD7:
            p['markers'].append([hex(m), i]); i += 2; continue
        if i+4 > len(data):
            p['err'] = 'truncated header'; break
        L = struct.unpack('>H', data[i+2:i+4])[0]
        if L < 2 or i+2+L > len(data):
            p['err'] = 'bad seg len %d at %d' % (L, i); break
        if m == 0xDA:
            ns = data[i+4]
            comps = []
            for k in range(ns):
                cid = data[i+5+2*k]; tc = data[i+6+2*k]
                comps.append([cid, tc >> 4, tc & 15])
            p['sos'] = {'off': i, 'len': L, 'ns': ns, 'comps': comps,
                        'Ss': data[i+5+2*ns], 'Se': data[i+6+2*ns], 'AhAl': data[i+7+2*ns],
                        'scan_start': i+2+L}
            p['markers'].append(['SOS', i, L])
            j = data.rfind(b'\xff\xd9')
            p['eoi'] = j if j >= 0 else None
            break
        seg = data[i+4:i+2+L]
        p['markers'].append([hex(m), i, L])
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            prec = seg[0]; hgt = struct.unpack('>H', seg[1:3])[0]; wid = struct.unpack('>H', seg[3:5])[0]; nc = seg[5]
            comps = []
            for k in range(nc):
                comps.append([seg[6+3*k], seg[7+3*k] >> 4, seg[7+3*k] & 15, seg[8+3*k]])
            p['sof'] = {'off': i, 'marker': hex(m), 'len': L, 'seg_off': i+4, 'prec': prec,
                        'h': hgt, 'w': wid, 'nc': nc, 'comps': comps}
        if m == 0xDB:
            p['dqt'].append({'off': i, 'seg_off': i+4, 'len': L, 'pq': seg[0] >> 4, 'tq': seg[0] & 15})
        if m == 0xC4:
            p['dht'].append({'off': i, 'seg_off': i+4, 'len': L, 'tc': seg[0] >> 4, 'th': seg[0] & 15})
        if m == 0xDD:
            p['dri'] = {'off': i, 'len': L, 'ri': struct.unpack('>H', seg[0:2])[0]}
        if m == 0xE0 and p['app0'] is None:
            p['app0'] = {'off': i, 'len': L}
        i += 2 + L
    return p

def put(b, off, nb):
    b = bytearray(b); b[off:off+len(nb)] = nb; return bytes(b)

def build_mutants(data, p):
    M = []
    def add(name, blob, note=''):
        M.append({'name': name, 'blob': blob, 'note': note})
    add('base_original', data, 'unchanged control')
    sof = p.get('sof'); sos = p.get('sos')
    eoi = p.get('eoi')
    if eoi:
        add('drop_eoi', data[:eoi], 'EOI marker removed')
    add('append_garbage16', data + b'\x00'*16, 'trailing bytes after EOI')
    add('append_ff_ff', data + b'\xff\xff', 'trailing garbage')
    add('trunc_95pct', data[:int(len(data)*0.95)], 'scan data truncated')
    add('insert_com_after_soi', b'\xff\xd8\xff\xfe\x00\x06ABCD' + data[2:], 'COM segment inserted')
    add('insert_app15_after_soi', b'\xff\xd8\xff\xef\x00\x06ABCD' + data[2:], 'APP15 inserted')
    add('insert_reserved_marker', b'\xff\xd8\xff\x02\x00\x04AB' + data[2:], 'reserved marker 0xFF02')
    add('dup_soi', b'\xff\xd8' + data, 'duplicate SOI')
    add('zeros_after_soi', b'\xff\xd8' + b'\x00'*8 + data[2:], '8 zero bytes after SOI')
    if p.get('app0'):
        a = p['app0']
        add('remove_app0', data[:a['off']] + data[a['off']+2+a['len']:], 'JFIF APP0 deleted')
        add('app0_len_plus2', put(data, a['off']+2, struct.pack('>H', a['len']+2)), 'APP0 length field +2')
    if sof:
        so = sof['seg_off']
        add('sof_prec_12', put(data, so, b'\x0c'), 'sample precision 12')
        add('sof_prec_0', put(data, so, b'\x00'), 'sample precision 0')
        add('sof_h_0', put(data, so+1, b'\x00\x00'), 'height = 0')
        add('sof_w_0', put(data, so+3, b'\x00\x00'), 'width = 0')
        add('sof_w_plus1', put(data, so+3, struct.pack('>H', sof['w']+1)), 'width+1 (breaks MCU tiling)')
        add('sof_w_big', put(data, so+3, struct.pack('>H', 8192)), 'width forced to 8192')
        add('sof_h_big', put(data, so+1, struct.pack('>H', 8192)), 'height forced to 8192')
        if sof['nc'] >= 1:
            add('sof_comp0_id_5', put(data, so+6, b'\x05'), 'component 0 id 1->5 (SOS mismatch)')
            add('sof_comp0_sampling_11', put(data, so+7, b'\x11'), 'component 0 H/V = 1x1')
            add('sof_comp0_sampling_22', put(data, so+7, b'\x22'), 'component 0 H/V = 2x2')
            add('sof_comp0_tq_3', put(data, so+8, b'\x03'), 'component 0 quant table 3')
        add('sof_nc_minus1', put(data, so+5, bytes([max(sof['nc']-1,1)])), 'number of components -1')
        add('sof0_to_sof2_progressive', put(data, sof['off']+1, b'\xc2'), 'baseline -> progressive SOF2')
        add('sof0_to_sof9_arithmetic', put(data, sof['off']+1, b'\xc9'), 'baseline -> arithmetic SOF9')
        add('sof0_to_sof3_lossless', put(data, sof['off']+1, b'\xc3'), 'baseline -> lossless SOF3')
    if p['dqt']:
        d = p['dqt'][0]
        add('dqt_pq_16bit', put(data, d['seg_off'], bytes([(1 << 4) | d['tq']])), 'DQT precision byte 0->16-bit')
        add('dqt_tq_3', put(data, d['seg_off'], bytes([(d['pq'] << 4) | 3])), 'DQT table id 0->3')
    if p['dht']:
        h0 = p['dht'][0]
        add('dht_tc_1_dc_to_ac', put(data, h0['seg_off'], bytes([(1 << 4) | h0['th']])), 'DHT class DC->AC')
        add('dht_th_3', put(data, h0['seg_off'], bytes([(h0['tc'] << 4) | 3])), 'DHT table id 0->3')
    if sos:
        s = sos['off']
        add('sos_ns_minus1', put(data, s+4, bytes([max(sos['ns']-1,1)])), 'SOS component count -1')
        add('sos_ss_1', put(data, s+5+2*sos['ns'], b'\x01'), 'SOS Ss = 1')
        add('sos_se_0', put(data, s+6+2*sos['ns'], b'\x00'), 'SOS Se = 0')
        add('sos_ahal_0x11', put(data, s+7+2*sos['ns'], b'\x11'), 'SOS Ah/Al = 1/1')
        add('insert_dri_ri1', data[:s] + b'\xff\xdd\x00\x04\x00\x01' + data[s:], 'DRI inserted (Ri=1, no RST markers)')
        add('insert_dri_ri0', data[:s] + b'\xff\xdd\x00\x04\x00\x00' + data[s:], 'DRI inserted (Ri=0)')
    return M

# ---------------- parent ----------------
def find_jpegs(root, maxdepth=5, maxfiles=200):
    res = []
    if not os.path.isdir(root):
        return res
    root = root.rstrip('\\')
    base = root.count('\\')
    for dp, dn, fn in os.walk(root):
        if dp.count('\\') - base >= maxdepth:
            dn[:] = []
        for f in fn:
            if f.lower().endswith(('.jpg', '.jpeg')):
                p = os.path.join(dp, f)
                try: res.append((os.path.getsize(p), p))
                except Exception: pass
                if len(res) >= maxfiles: return res
    return res

def main():
    R = {'cwd': WS}
    cands = []
    for root in (os.path.join(WS, 'imgs'), r'C:\Windows\Web', r'C:\Windows\System32',
                 r'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.4'):
        cands += find_jpegs(root)
    cands.sort()
    R['found_jpegs'] = [[s, p] for s, p in cands[:25]]
    base = None
    for s, p in cands:
        try:
            d = open(p, 'rb').read()
        except Exception:
            continue
        info = parse_jpeg(d)
        if info.get('sof') and info.get('sos') and info.get('eoi'):
            base = (p, d, info); break
    if base is None:
        R['fatal'] = 'no real JPEG with SOF+SOS+EOI found'
        print(json.dumps(R, indent=1)); return
    p, data, info = base
    R['base_image'] = p
    R['base_size'] = len(data)
    R['base_sof'] = info['sof']
    R['base_sos'] = {k: info['sos'][k] for k in ('ns','Ss','Se','AhAl')}
    R['base_dri'] = info['dri']
    R['base_markers'] = info['markers'][:20]
    os.makedirs(MUT, exist_ok=True)
    muts = build_mutants(data, info)
    manifest = []
    for m in muts:
        fp = os.path.join(MUT, m['name'] + '.jpg')
        open(fp, 'wb').write(m['blob'])
        manifest.append({'name': m['name'], 'path': fp, 'note': m['note']})
    mpath = os.path.join(WS, 'manifest.json')
    json.dump(manifest, open(mpath, 'w'))
    R['mutants'] = [[m['name'], m['note'], len(m['blob'])] for m in manifest]

    allres = {}
    for tag, dll, bindir in NVJ:
        cudart = find_cudart(bindir)
        if not os.path.exists(dll):
            allres[tag] = {'missing_dll': dll}; continue
        cmd = [sys.executable, os.path.abspath(__file__), 'worker', dll, bindir, cudart or '', mpath]
        t0 = __import__('time').time()
        try:
            pr = subprocess.run(cmd, capture_output=True, timeout=600)
        except Exception as e:
            allres[tag] = {'spawn_error': repr(e)}; continue
        dt = round(__import__('time').time()-t0, 2)
        out = pr.stdout.decode('utf-8', 'replace')
        entry = {'rc': pr.returncode, 'secs': dt}
        try:
            j = json.loads(out)
            entry.update(j)
        except Exception:
            entry['raw_stdout_tail'] = out[-3000:]
            entry['raw_stderr_tail'] = pr.stderr.decode('utf-8','replace')[-2000:]
        allres[tag] = entry
    R['nvjpeg'] = allres
    json.dump(R, open(os.path.join(WS, 'jpeg_probe2.json'), 'w'), indent=1)
    print(json.dumps(R, indent=1))

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'worker':
        try:
            out = worker(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        except Exception:
            out = {'worker_exception': traceback.format_exc()}
        print(json.dumps(out))
    else:
        main()
