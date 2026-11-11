import ctypes, os, sys, json, hashlib, struct, traceback

R = {}

def note(k, v):
    R[k] = v

# ---------- python env ----------
try:
    from PIL import Image
    import PIL
    note('PIL', getattr(PIL, '__version__', 'present'))
except Exception as e:
    note('PIL', 'missing: %r' % (e,))
try:
    import numpy
    note('numpy', numpy.__version__)
except Exception as e:
    note('numpy', 'missing: %r' % (e,))

os.makedirs('imgs', exist_ok=True)

# ---------- image generation ----------
def minimal_gray_jpeg(w=32, h=32, tag='m'):
    qt = bytes([1] * 64)
    out = bytearray()
    out += b'\xFF\xD8'
    out += b'\xFF\xDB' + struct.pack('>H', 67) + bytes([0x00]) + qt
    out += b'\xFF\xC0' + struct.pack('>H', 11) + bytes([8]) + struct.pack('>HH', h, w) + bytes([1, 1, 0x11, 0])
    dc_counts = bytes([1] + [0] * 15); dc_vals = bytes([0x00])
    out += b'\xFF\xC4' + struct.pack('>H', 2 + 1 + 16 + 1) + bytes([0x00]) + dc_counts + dc_vals
    ac_counts = bytes([1] + [0] * 15); ac_vals = bytes([0x00])
    out += b'\xFF\xC4' + struct.pack('>H', 2 + 1 + 16 + 1) + bytes([0x10]) + ac_counts + ac_vals
    out += b'\xFF\xDA' + struct.pack('>H', 8) + bytes([1, 1, 0x00, 0, 63, 0])
    nblocks = ((w + 7) // 8) * ((h + 7) // 8)
    bits = '00' * nblocks
    while len(bits) % 8:
        bits += '1'
    out += bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    out += b'\xFF\xD9'
    return bytes(out)

made = {}
try:
    from PIL import Image
    im = Image.new('RGB', (64, 48))
    px = im.load()
    for y in range(48):
        for x in range(64):
            px[x, y] = (x * 4 % 256, y * 5 % 256, (x + y) * 3 % 256)
    p = os.path.join('imgs', 'pil_rgb_420.jpg')
    im.save(p, quality=90, subsampling=2)
    made['pil_rgb_420'] = p
    p2 = os.path.join('imgs', 'pil_rgb_444.jpg')
    im.save(p2, quality=90, subsampling=0)
    made['pil_rgb_444'] = p2
    p3 = os.path.join('imgs', 'pil_rgb_422.jpg')
    im.save(p3, quality=90, subsampling=1)
    made['pil_rgb_422'] = p3
    p4 = os.path.join('imgs', 'pil_gray.jpg')
    im.convert('L').save(p4, quality=90)
    made['pil_gray'] = p4
    p5 = os.path.join('imgs', 'pil_progressive.jpg')
    im.save(p5, quality=90, progressive=True)
    made['pil_progressive'] = p5
except Exception as e:
    made['pil_error'] = repr(e)

hand = os.path.join('imgs', 'hand_gray.jpg')
try:
    open(hand, 'wb').write(minimal_gray_jpeg(32, 32))
    made['hand_gray'] = hand
except Exception as e:
    made['hand_error'] = repr(e)

note('images', made)
note('image_sha', {k: hashlib.sha256(open(v, 'rb').read()).hexdigest()[:16] for k, v in made.items() if isinstance(v, str) and os.path.exists(v)})

# ---------- nvjpeg ----------
STATUS = {0: 'SUCCESS', 1: 'NOT_INITIALIZED', 2: 'INVALID_PARAMETER', 3: 'BAD_JPEG',
          4: 'JPEG_NOT_SUPPORTED', 5: 'ALLOCATOR_FAILURE', 6: 'EXECUTION_FAILED',
          7: 'ARCH_MISMATCH', 8: 'INTERNAL_ERROR', 9: 'IMPLEMENTATION_NOT_SUPPORTED'}
CSS = {0: '444', 1: '422', 2: '420', 3: '440', 4: '411', 5: '410', 6: 'GRAY', 7: '410V'}

class JImage(ctypes.Structure):
    _fields_ = [('channel', ctypes.c_void_p * 4), ('pitch', ctypes.c_size_t * 4)]

DLLS = [
    r'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2\bin\nvjpeg64_11.dll',
    r'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.4\bin\nvjpeg64_12.dll',
    r'D:\cuda1341_extract\libnvjpeg\nvjpeg\bin\x64\nvjpeg64_13.dll',
]

_keep = []

def decode_one(lib, data, outfmt=2):
    h = ctypes.c_void_p()
    s = lib.nvjpegCreateSimple(ctypes.byref(h))
    if s != 0:
        return {'create': STATUS.get(s, s)}
    res = {}
    try:
        nc = ctypes.c_int(0)
        css = ctypes.c_int(-1)
        wa = (ctypes.c_int * 4)()
        ha = (ctypes.c_int * 4)()
        buf = ctypes.create_string_buffer(data, len(data))
        s = lib.nvjpegGetImageInfo(h, ctypes.cast(buf, ctypes.c_char_p), ctypes.c_size_t(len(data)),
                                   ctypes.byref(nc), ctypes.byref(css), wa, ha)
        res['getinfo'] = STATUS.get(s, s)
        if s == 0:
            res['ncomp'] = nc.value
            res['css'] = CSS.get(css.value, css.value)
            res['widths'] = list(wa)
            res['heights'] = list(ha)
        w = wa[0] if wa[0] else 0
        hgt = ha[0] if ha[0] else 0
        if w and hgt:
            sz = w * hgt * 3
            obuf = ctypes.create_string_buffer(sz)
            img = JImage()
            img.channel[0] = ctypes.cast(obuf, ctypes.c_void_p)
            img.pitch[0] = w * 3
            st = ctypes.c_void_p()
            s2 = lib.nvjpegJpegStateCreate(h, ctypes.byref(st))
            res['state_create'] = STATUS.get(s2, s2)
            if s2 == 0:
                s3 = lib.nvjpegDecode(h, st, ctypes.cast(buf, ctypes.c_char_p), ctypes.c_size_t(len(data)),
                                      ctypes.c_int(outfmt), ctypes.byref(img), ctypes.c_void_p(0))
                res['decode'] = STATUS.get(s3, s3)
                if s3 == 0:
                    raw = obuf.raw[:sz]
                    res['sha256_16'] = hashlib.sha256(raw).hexdigest()[:16]
                    res['mean'] = round(sum(raw) / float(sz), 3)
                    res['first6'] = list(raw[:6])
                lib.nvjpegJpegStateDestroy(st)
    except Exception as e:
        res['exc'] = repr(e)
    finally:
        lib.nvjpegDestroy(h)
    return res

out = {}
for path in DLLS:
    ent = {'exists': os.path.exists(path)}
    if ent['exists']:
        ent['size'] = os.path.getsize(path)
    try:
        dh = os.add_dll_directory(os.path.dirname(path))
        _keep.append(dh)
        lib = ctypes.CDLL(path)
        lib.nvjpegCreateSimple.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        lib.nvjpegCreateSimple.restype = ctypes.c_int
        lib.nvjpegDestroy.argtypes = [ctypes.c_void_p]
        lib.nvjpegDestroy.restype = ctypes.c_int
        lib.nvjpegGetImageInfo.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                           ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
                                           ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
        lib.nvjpegGetImageInfo.restype = ctypes.c_int
        lib.nvjpegJpegStateCreate.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        lib.nvjpegJpegStateCreate.restype = ctypes.c_int
        lib.nvjpegJpegStateDestroy.argtypes = [ctypes.c_void_p]
        lib.nvjpegJpegStateDestroy.restype = ctypes.c_int
        lib.nvjpegDecode.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                     ctypes.c_int, ctypes.POINTER(JImage), ctypes.c_void_p]
        lib.nvjpegDecode.restype = ctypes.c_int
        ver = {}
        try:
            for name, t in (('major', 0), ('minor', 1), ('patch', 2)):
                v = ctypes.c_int(0)
                r = lib.nvjpegGetProperty(t, ctypes.byref(v))
                ver[name] = [STATUS.get(r, r), v.value]
        except Exception as e:
            ver['error'] = repr(e)
        ent['version'] = ver
        ent['decodes'] = {}
        for name, p in made.items():
            if isinstance(p, str) and os.path.exists(p):
                ent['decodes'][name] = decode_one(lib, open(p, 'rb').read())
        ent['load'] = 'ok'
    except Exception as e:
        ent['load'] = 'FAILED: %r' % (e,)
        ent['trace'] = traceback.format_exc()[-600:]
    out[path] = ent

note('nvjpeg', out)
print(json.dumps(R, indent=1, default=str))
