# P22 CUDA Toolkit CVE inventory

Collected from NVIDIA Product Security bulletins (primary) with NVD used for cross-check.
Only CVEs whose bulletin text was actually fetched are marked *verified*; the rest are
recorded from search results and flagged as such. Nothing here is inferred from the
product name alone.

| CVE | Component | CWE | Affected | Fixed | Bulletin | Source status |
|---|---|---|---|---|---|---|
| CVE-2024-53870 | cuobjdump | CWE-125 OOB read | <= 12.8 | 12.8 | a_id | search result only |
| CVE-2024-53871 | nvdisasm | CWE-125 OOB read | <= 12.8 | 12.8 | a_id | search result only |
| CVE-2024-53872 | cuobjdump | CWE-125 OOB read | <= 12.8 | 12.8 | a_id | search result only |
| CVE-2024-53873 | cuobjdump (Windows) | CWE-125 OOB read | <= 12.8 | 12.8 | a_id | search result only |
| CVE-2024-53874 | cuobjdump | CWE-125 OOB read | <= 12.8 | 12.8 | a_id | search result only |
| CVE-2024-53875 | cuobjdump | CWE-125 OOB read | <= 12.8 | 12.8 | a_id | search result only |
| CVE-2024-53876 | nvdisasm | CWE-125 OOB read | <= 12.8 | 12.8 | a_id | search result only |
| CVE-2024-53877 | nvdisasm | CWE-476 NULL deref | <= 12.8 | 12.8 | a_id | search result only |
| CVE-2024-53878 | cuobjdump | CWE-1284 invalid length | <= 12.8 | 12.8 | a_id | search result only |
| CVE-2024-53879 | cuobjdump | CWE-1284 invalid length | <= 12.8 | 12.8 | a_id | search result only |
| CVE-2025-23248 | nvdisasm | CWE-125 OOB read | < 13.0 | 13.0 | a_id | search result only |
| CVE-2025-23255 | cuobjdump | CWE-125 OOB read | < 13.0 | 13.0 | a_id | search result only |
| CVE-2025-23271 | nvdisasm | CWE-125 OOB read | < 13.0 | 13.0 | a_id | search result only |
| CVE-2025-23273 | nvJPEG | CWE-369 div by zero | nvJPEG < 13.0.0 | nvJPEG 13.0.0 | a_id | search result only |
| CVE-2025-23274 | nvJPEG | CWE-125 OOB read | nvJPEG < 13.0.0 | nvJPEG 13.0.0 | a_id | search result only |
| CVE-2025-23275 | nvJPEG | CWE-787 OOB write | nvJPEG < 13.0.0 | nvJPEG 13.0.0 | a_id | search result only |
| CVE-2025-23308 | nvdisasm | CWE-122 heap overflow (REL parsing) | < 13.0 | 13.0 | a_id | search result only |
| CVE-2025-23338 | nvdisasm | CWE-129 invalid index | < 13.0 | 13.0 | a_id | search result only |
| CVE-2025-23339 | cuobjdump | CWE-121 stack overflow (DWARF) | < 13.0 | 13.0 | a_id | search result only |
| CVE-2025-23340 | nvdisasm | CWE-125 OOB read | < 13.0 | 13.0 | a_id | search result only |
| CVE-2025-23346 | cuobjdump | CWE-476 NULL deref | < 13.0 | 13.0 | a_id | search result only |
| CVE-2025-23247 | cuobjdump | CWE-130 length check | <= 12.9 | 12.9 | a_id | search result only |
| CVE-2024-0124 | nvdisasm | CWE-416 UAF | <= 12.6U1 | 12.6U2 | a_id | search result only |
| CVE-2024-0109 | cuobjdump | CWE-125 | <= 12.6 | 12.6U1 | a_id | search result only |
| CVE-2024-0110 | cuobjdump | CWE-125 | <= 12.6 | 12.6U1 | a_id | search result only |
| CVE-2024-0111 | cuobjdump | CWE-476 | <= 12.6 | 12.6U1 | a_id | search result only |

## By component

| component | count |
|---|---|
| cuobjdump | 14 |
| nvdisasm | 9 |
| nvJPEG | 3 |

## Families deliberately not counted as CUDA Toolkit

Driver CVEs (GPU KMD) are out of scope for this backend: containers share the WSL2
kernel and the Windows driver, so a driver-level test needs a VM. nvJPEG entries are
marked separately because they ship both inside the toolkit and as a standalone
library, and the bulletin's fixed versions differ (13.0 vs nvJPEG 13.0.0 / 25.03).
