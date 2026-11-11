import os, sys, glob, json

def sec(t):
    print("\n==== " + t + " ====")

CUDA_ROOT = r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA"
print("python", sys.version.replace("\n"," "))
print("exe", sys.executable)
sec("cwd")
print(os.getcwd())
try:
    print("ws:", sorted(os.listdir(".")))
except Exception as e:
    print("ERR ws", e)

sec("cuda root")
try:
    print(sorted(os.listdir(CUDA_ROOT)))
except Exception as e:
    print("ERR", e)

for ver in ["v11.2", "v12.4", "v13.4"]:
    d = os.path.join(CUDA_ROOT, ver)
    sec("cuda " + ver + " -> " + d)
    if not os.path.isdir(d):
        print("MISSING")
        continue
    try:
        print("top:", sorted(os.listdir(d)))
    except Exception as e:
        print("ERR top", e)
    for sub in ["bin", "include", "lib", "lib\\x64", "lib\\Win32"]:
        p = os.path.join(d, sub)
        if os.path.isdir(p):
            try:
                hits = [n for n in sorted(os.listdir(p)) if "nvjpeg" in n.lower() or n.lower() in ("nvjpeg.h",)]
            except Exception as e:
                hits = ["ERR %s" % e]
            print(sub, "->", hits)
        else:
            print(sub, "-> (no dir)")

sec("D:\\cuda1341_extract")
for root in [r"D:\cuda1341_extract"]:
    if os.path.isdir(root):
        for dirpath, dirnames, filenames in os.walk(root):
            for f in filenames:
                if "nvjpeg" in f.lower():
                    fp = os.path.join(dirpath, f)
                    try:
                        sz = os.path.getsize(fp)
                    except Exception:
                        sz = -1
                    print(sz, fp)
    else:
        print("missing", root)

# version resources
import ctypes
from ctypes import wintypes

def file_version(path):
    try:
        size = ctypes.windll.version.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(path, 0, size, buf):
            return None
        r = ctypes.c_void_p(); l = wintypes.UINT()
        if not ctypes.windll.version.VerQueryValueW(buf, "\\", ctypes.byref(r), ctypes.byref(l)):
            return None
        class VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [("dwSignature", wintypes.DWORD), ("dwStrucVersion", wintypes.DWORD),
                        ("dwFileVersionMS", wintypes.DWORD), ("dwFileVersionLS", wintypes.DWORD),
                        ("dwProductVersionMS", wintypes.DWORD), ("dwProductVersionLS", wintypes.DWORD),
                        ("dwFileFlagsMask", wintypes.DWORD), ("dwFileFlags", wintypes.DWORD),
                        ("dwFileOS", wintypes.DWORD), ("dwFileType", wintypes.DWORD),
                        ("dwFileSubtype", wintypes.DWORD), ("dwFileDateMS", wintypes.DWORD),
                        ("dwFileDateLS", wintypes.DWORD)]
        fi = VS_FIXEDFILEINFO.from_address(r.value)
        return "%d.%d.%d.%d" % (fi.dwFileVersionMS >> 16, fi.dwFileVersionMS & 0xFFFF,
                                 fi.dwFileVersionLS >> 16, fi.dwFileVersionLS & 0xFFFF)
    except Exception as e:
        return "ERR %s" % e

sec("nvjpeg dll version resources")
dlls = [
    r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.2\bin\nvjpeg64_11.dll",
    r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.4\bin\nvjpeg64_12.dll",
    r"D:\cuda1341_extract\libnvjpeg\nvjpeg\bin\x64\nvjpeg64_13.dll",
]
for d in dlls:
    print(d, "exists=" + str(os.path.isfile(d)), "ver=" + str(file_version(d) if os.path.isfile(d) else None))

sec("load each dll with ctypes")
for d in dlls:
    if not os.path.isfile(d):
        continue
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.LoadLibraryExW.restype = wintypes.HMODULE
        kernel32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
        h = kernel32.LoadLibraryExW(d, None, 0x00000001 | 0x00001000)  # DONT_RESOLVE_DLL_REFERENCES | ALTERED_SEARCH_PATH
        if not h:
            print("LOAD FAIL", d, "err", ctypes.get_last_error())
        else:
            print("LOAD OK", d, "handle", h)
    except Exception as e:
        print("LOAD EXC", d, e)

sec("python packages")
for m in ["numpy", "PIL", "cv2", "ctypes"]:
    try:
        mod = __import__(m)
        print(m, "OK", getattr(mod, "__version__", ""))
    except Exception as e:
        print(m, "MISSING", e)

sec("nvcc")
try:
    print(os.path.isfile(r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.4\bin\nvcc.EXE"))
except Exception as e:
    print(e)
