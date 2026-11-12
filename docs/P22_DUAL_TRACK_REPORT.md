# P22 dual-track report

Two tracks, counted separately. A finding never counts as a reproduced CVE, and a reproduced
CVE never absorbs an unrelated crash.

## Track A — assigned CVE

| CVE | component | assigned | reproduced | status |
|---|---|---|---|---|
| CVE-2024-0124 | nvdisasm, CWE-416 UAF, <= 12.6U1 | yes | **no** | not reproduced |

What was established: version identity of every build used (12.6.68 / 12.8.55 / 12.8.90 /
13.0.85), and that six crafted inputs (truncation, huge `e_shnum`, out-of-range `e_shoff`,
`.nv.info` size, symtab link, shstrtab name offset) are all rejected before the UAF path,
with identical behaviour across builds. No input produced a signal.

Why it is not "reproduced": a use-after-free needs a lifetime violation, and nothing in this
campaign demonstrated one. Absence of a crash in four builds is not evidence of absence of the
bug either; it means no trigger was found. Both statements are recorded as they are.

## Track B — findings discovered while doing A

| finding | component | class | builds affected | stable | root cause | CVE link | status |
|---|---|---|---|---|---|---|---|
| `FND-t22-0001` | nvdisasm | SIGSEGV | 12.6.68 only | no (1 run) | not started | candidate: 23308 / 53876 / 23338 | new |

`FND-t22-0001` is the `rel_offset_huge` crash: the first relocation offset is set to
`0xFFFFFFFFFFFF0000`, and nvdisasm 12.6.68 dies with a supervisor-verified SIGSEGV while
12.8.55, 12.8.90 and 13.0.85 reject the file with `fatal : Relocation offset outside section`.
It is linked to candidate CVEs but **not attributed** to any: 12.6.68 sits inside several
advisory ranges at once, and there is no stack.

Tally from the store (`FindingStore.tally()`): findings=1, stable=0, root-caused=0,
linked-to-a-known-CVE=1, unattributed=0, by component {nvdisasm: 1}, by class {SIGSEGV: 1}.

## The mechanism

- `finding_new` / `finding_update` / `finding_list` are agent tools; the agent decides when an
  observation is a finding. Nothing auto-promotes a crash, and nothing auto-links a CVE.
- Ids are `FND-<trial>-0001`; `Finding.__post_init__` refuses an id that looks like a CVE, so a
  finding cannot be cited as an advisory number.
- Each finding gets a JSON record, an advisory-style Markdown report, and a journal line.
  Updates append a revision and keep the previous one under `research/findings/history/`.
- Reports print `UNKNOWN` where the evidence does not support a value (CWE, impact, stability).

## What remains unproven

`FND-t22-0001` has one run, no dump and no stack. Its CWE therefore stays UNKNOWN even though
the crash class is certainly SIGSEGV, and its relation to CVE-2025-23308 is a hypothesis the
next experiment has to test, not a conclusion.
