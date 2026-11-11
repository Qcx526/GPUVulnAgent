import os, sys, glob, struct, hashlib, ctypes, traceback, time
from ctypes import c_int, c_void_p, c_size_t, POINTER, byref, cast, create_string_buffer

def log(*a):
    print(*a, flush=True)

CUDA = "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA"
DLLS = [
 ("11.2", os.path.normpath(CUDA + "/v11.2/bin/nvjpeg64_11.dll")),
 ("12.4", os.path.normpath(CUDA + "/v12.4/bin/nvjpeg64_12.dll")),
 ("13.4", os.path.normpath("D:/cuda1341_extract/libnvjpeg/nvjpeg/bin/x64/nvjpeg64_13.dll")),
]
CUDART = os.path.normpath(CUDA + "/v12.4/bin/cudart64_12.dll")

class NvjpegImage(ctypes.Structure):
    _fields_ = [("channel", c_void_p*4), ("pitch", c_size_t*4)]

class Cudart:
    def __init__(self, path):
        os.add_dll_directory(os.path.dirname(path))
        self.dll = ctypes.WinDLL(path)
        d = self.dll
        d.cudaMalloc.argtypes = [POINTER(c_void_p), c_size_t]; d.cudaMalloc.restype = c_int
        d.cudaFree.argtypes = [c_void_p]; d.cudaFree.restype = c_int
        d.cudaMemcpy.argtypes = [c_void_p, c_void_p, c_size_t, c_int]; d.cudaMemcpy.restype = c_int
        d.cudaDeviceSynchronize.argtypes = []; d.cudaDeviceSynchronize.restype = c_int
    def malloc(self, n):
        p = c_void_p(); r = self.dll.cudaMalloc(byref(p), c_size_t(int(n))); return r, p
    def d2h(self, dst, src, n):
        return self.dll.cudaMemcpy(cast(dst, c_void_p), src, c_size_t(int(n)), 2)

class Nvjpeg:
    def __init__(self, ver, path):
        self.ver = ver; self.path = path; self.loaderr = None
        self.handle = c_void_p(); self.state = c_void_p()
        self.props = [None]*4; self.create_status = None; self.state_status = None
        try:
            d0 = os.path.dirname(path)
            if os.path.isdir(d0):
                os.add_dll_directory(d0)
            self.dll = ctypes.WinDLL(path)
            d = self.dll
            d.nvjpegGetProperty.argtypes = [c_int, POINTER(c_int)]; d.nvjpegGetProperty.restype = c_int
            d.nvjpegCreateSimple.argtypes = [POINTER(c_void_p)]; d.nvjpegCreateSimple.restype = c_int
            d.nvjpegJpegStateCreate.argtypes = [c_void_p, POINTER(c_void_p)]; d.nvjpegJpegStateCreate.restype = c_int
            d.nvjpegGetImageInfo.argtypes = [c_void_p, c_void_p, c_size_t, POINTER(c_int), POINTER(c_int), POINTER(c_int), POINTER(c_int)]
            d.nvjpegGetImageInfo.restype = c_int
            d.nvjpegDecode.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t, c_int, POINTER(NvjpegImage)]
            d.nvjpegDecode.restype = c_int
        except Exception as e:
            self.loaderr = repr(e); return
        for i in range(4):
            v = c_int(-1)
            try:
                r = d.nvjpegGetProperty(i, byref(v))
            except Exception:
                r = -1
            if r == 0: self.props[i] = v.value
        self.create_status = d.nvjpegCreateSimple(byref(self.handle))
        if self.create_status == 0:
            self.state_status = d.nvjpegJpegStateCreate(self.handle, byref(self.state))

    def info(self, data):
        buf = create_string_buffer(data, len(data))
        nc = c_int(0); sub = c_int(0); w = (c_int*4)(); h = (c_int*4)()
        r = self.dll.nvjpegGetImageInfo(self.handle, cast(buf, c_void_p), c_size_t(len(data)), byref(nc), byref(sub), w, h)
        return [r, nc.value, sub.value, [w[i] for i in range(4)], [h[i] for i in range(4)]]

    def decode(self, data, cud):
        gi = self.info(data)
        if gi[0] != 0:
            return gi[0], gi, None
        W = gi[3][0]; H = gi[4][0]
        if W <= 0 or H <= 0 or W > 20000 or H > 20000:
            return -2000, gi, None
        nbytes = W*3*H
        cr, dp = cud.malloc(max(nbytes, 256))
        if cr != 0:
            return -1000-cr, gi, None
        img = NvjpegImage()
        img.channel[0] = dp; img.pitch[0] = c_size_t(W*3)
        buf = create_string_buffer(data, len(data))
        st = self.dll.nvjpegDecode(self.handle, self.state, cast(buf, c_void_p), c_size_t(len(data)), 5, byref(img))
        out = None
        if st == 0:
            cud.dll.cudaDeviceSynchronize()
            hb = create_string_buffer(nbytes)
            mr = cud.d2h(hb, dp, nbytes)
            if mr == 0:
                out = bytes(hb.raw[:nbytes])
        cud.dll.cudaFree(dp)
        return st, gi, out

SEGNAME = {0xD8:'SOI',0xD9:'EOI',0xDA:'SOS',0xDB:'DQT',0xC4:'DHT',0xDD:'DRI',0xC0:'SOF0',0xC1:'SOF1',0xC2:'SOF2',0xE0:'APP0',0xE1:'APP1',0xEE:'APP14',0xFE:'COM'}

def segs(data):
    out = []
    n = len(data)
    if data[:2] != b'\xff\xd8':
        return out
    i = 2
    while i + 1 < n:
        if data[i] != 0xFF:
            break
        m = data[i+1]
        if m == 0xD8 or m == 0x01 or (0xD0 <= m <= 0xD7):
            out.append((i, m, i+2, i+2)); i += 2; continue
        if m == 0xD9:
            out.append((i, m, i+2, i+2)); break
        if i + 3 >= n:
            break
        L = struct.unpack('>H', data[i+2:i+4])[0]
        end = i + 2 + L
        if L < 2 or end > n:
            out.append((i, m, i+4, n)); break
        out.append((i, m, i+4, end))
        if m == 0xDA:
            j = end
            while j + 1 < n:
                if data[j] == 0xFF:
                    m2 = data[j+1]
                    if m2 != 0x00 and not (0xD0 <= m2 <= 0xD7):
                        break
                    j += 2; continue
                j += 1
            i = j; continue
        i = end
    return out

def rm(data, ss):
    for s in sorted(ss, key=lambda x: -x[0]):
        data = data[:s[0]] + data[s[3]:]
    return data

def build_muts(data):
    S = segs(data)
    by = {}
    for s in S:
        by.setdefault(s[1], []).append(s)
    muts = []
    muts.append(('baseline', data))
    muts.append(('soi_ffd8_to_ffd9', b'\xff\xd9' + data[2:]))
    muts.append(('eoi_removed', data[:-2] if data[-2:] == b'\xff\xd9' else data))
    if 0xE0 in by: muts.append(('drop_APP0', rm(data, by[0xE0])))
    if 0xDB in by: muts.append(('drop_DQT', rm(data, by[0xDB])))
    if 0xC4 in by: muts.append(('drop_DHT', rm(data, by[0xC4])))
    if 0xC0 in by:
        s = by[0xC0][0]
        muts.append(('drop_SOF0', rm(data, [s])))
        muts.append(('SOF0_marker_to_SOF1_0xC1', data[:s[0]+1] + b'\xc1' + data[s[0]+2:]))
        muts.append(('SOF0_marker_to_SOF2_0xC2', data[:s[0]+1] + b'\xc2' + data[s[0]+2:]))
        nf_off = s[2] + 5
        if nf_off < s[3]:
            muts.append(('SOF_Nf_3_to_4', data[:nf_off] + b'\x04' + data[nf_off+1:]))
        samp_off = s[2] + 6 + 1
        if samp_off < s[3]:
            old = data[samp_off:samp_off+1]
            muts.append(('SOF_Y_sampling_%02x_to_11' % data[samp_off], data[:samp_off] + b'\x11' + data[samp_off+1:]))
    if 0xDB in by:
        q = by[0xDB][0]
        muts.append(('DQT_Pq_8bit_to_16bit_flag', data[:q[2]] + bytes([data[q[2]] | 0x10]) + data[q[2]+1:]))
    if 0xDA in by:
        s = by[0xDA][0]
        muts.append(('truncate_at_SOS', data[:s[0]]))
        muts.append(('truncate_at_SOS_plus_EOI', data[:s[0]] + b'\xff\xd9'))
        muts.append(('SOS_Ns_3_to_4', data[:s[2]] + b'\x04' + data[s[2]+1:]))
        muts.append(('zero_entropy_scan', data[:s[3]] + b'\x00' * (len(data) - s[3])))
    muts.append(('truncate_half', data[:len(data)//2]))
    muts.append(('append_1KB_zeros', data + b'\x00'*1024))
    muts.append(('insert_unknown_marker_FFC9', data[:2] + b'\xff\xc9\x00\x04\x00\x00' + data[2:]))
    return muts

log('=== cudart ===')
cud = None
try:
    cud = Cudart(CUDART)
    log('loaded', CUDART)
except Exception as e:
    log('cudart load failed:', repr(e))

log('=== nvjpeg dlls ===')
libs = {}
for ver, p in DLLS:
    if not os.path.exists(p):
        log('DLL', ver, 'MISSING', p); continue
    stt = os.stat(p)
    meta = 'size=%d mtime=%s' % (stt.st_size, time.strftime('%Y-%m-%d', time.localtime(stt.st_mtime)))
    h = hashlib.sha256(open(p,'rb').read()).hexdigest()[:16]
    try:
        nv = Nvjpeg(ver, p)
    except Exception as e:
        log('DLL', ver, meta, 'ctor_error', repr(e)); continue
    if nv.loaderr:
        log('DLL', ver, meta, 'load_error=', nv.loaderr); continue
    log('DLL', ver, meta, 'sha256_16=', h, 'nvjpeg_version(major,minor,patch,build)=', nv.props, 'create=', nv.create_status, 'state=', nv.state_status)
    libs[ver] = nv

log('=== sample jpeg search ===')
pats = [
  os.path.normpath('C:/Windows/Web/**/*.jpg'),
  os.path.normpath('C:/Users/Public/Pictures/**/*.jpg'),
  os.path.normpath('C:/ProgramData/NVIDIA Corporation/**/*.jpg'),
  os.path.normpath(CUDA + '/**/*.jpg'),
  os.path.normpath(os.getcwd() + '/**/*.jpg'),
]
cands = []
for pat in pats:
    try:
        got = glob.glob(pat, recursive=True)
        cands += got
        log('pattern', pat, '->', len(got))
    except Exception as e:
        log('pattern', pat, 'err', repr(e))
log('total jpg candidates', len(cands))
best = None
for c in cands:
    try:
        d = open(c, 'rb').read()
    except Exception:
        continue
    if len(d) < 100 or len(d) > 4*1024*1024 or d[:2] != b'\xff\xd8':
        continue
    S = segs(d)
    mk = [s[1] for s in S]
    if 0xC0 in mk and 0xDA in mk and 0xD9 in mk:
        if best is None or len(d) < len(best[1]):
            best = (c, d)
if best is None:
    for c in cands:
        try:
            d = open(c, 'rb').read()
        except Exception:
            continue
        if d[:2] == b'\xff\xd8' and 0xDA in [s[1] for s in segs(d)]:
            best = (c, d); break
if best is None:
    log('NO_USABLE_JPEG_FOUND')
    sys.exit(0)
spath, sdata = best
S = segs(sdata)
log('chosen', spath, 'bytes', len(sdata), 'sha256_16', hashlib.sha256(sdata).hexdigest()[:16])
log('segments', ' '.join((SEGNAME.get(s[1], hex(s[1]))) + '@' + str(s[0]) for s in S))
sof = [s for s in S if s[1] in (0xC0,0xC1,0xC2)]
if sof:
    s = sof[0]
    log('SOF marker=0x%02X payload_first8=%s' % (s[1], sdata[s[2]:s[2]+8].hex()))

log('=== baseline decode per version ===')
base = {}
for ver in ('12.4','11.2','13.4'):
    nv = libs.get(ver)
    if nv is None:
        log('baseline', ver, 'not_loaded'); continue
    if cud is None:
        log('baseline', ver, 'no cudart'); continue
    try:
        st, gi, out = nv.decode(sdata, cud)
        md5 = hashlib.md5(out).hexdigest()[:12] if out else '-'
        nz = sum(1 for b in out[:8192] if b) if out else -1
        log('baseline v%s gi=%s ncomp=%s sub=%s wh=%sx%s dec_status=%s md5=%s nonzero_first8k=%s' % (ver, gi[0], gi[1], gi[2], gi[3][0], gi[4][0], st, md5, nz))
        if out: base[ver] = md5
    except Exception as e:
        log('baseline', ver, 'exception', repr(e))

log('=== mutations on 12.4 ===')
nv = libs.get('12.4') or (list(libs.values())[0] if libs else None)
if nv is None or cud is None:
    log('cannot run mutations')
else:
    log('using version', nv.ver)
    for label, md in build_muts(sdata):
        try:
            st, gi, out = nv.decode(md, cud)
            md5 = hashlib.md5(out).hexdigest()[:12] if out else '-'
            nz = sum(1 for b in out[:4096] if b) if out else -1
            same = 'same' if (out and md5 == base.get(nv.ver)) else ('diff' if out else '-')
            log('MUT %-30s len=%6d gi=%2s ncomp=%s sub=%s %sx%s dec=%3s md5=%-12s nz4k=%-5s %s' % (label, len(md), gi[0], gi[1], gi[2], gi[3][0], gi[4][0], st, md5, nz, same))
        except Exception as e:
            log('MUT', label, 'exception', repr(e))
log('=== done ===')
