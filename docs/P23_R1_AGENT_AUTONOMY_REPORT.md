# P23-R1 agent autonomy report

Blind run: only the CVE id, the environment facts and the budget were given. Real DeepSeek and
Tavily, 14m23s, 30 decisions, 43 tool turns, 36 container executions, 1,286,497 tokens
(1,244,793 prompt / 41,704 completion), 92 artifacts, 106 evidence records (chain verified).

| capability | result |
|---|---|
| read the advisory itself | yes: a_id/5577 + NVD JSON, CWE-416, <= 12.6U1, fixed 12.6U2 |
| searched itself | yes: web_extract, http_get, toolchain_lookup, memory_search |
| acquired versions itself | yes: signed APT repo, gpgv good, deb sha256 matched, --version 12.6.68 / 12.6.77 |
| generated a PoC itself | yes: baseline nvcc -rdc sm_75 cubin, then its own reloc_off_outside variant |
| mutated itself | yes: reloc_sym_oob and a masking control (r_offset = section_size + 1) |
| used failure as feedback | yes: moved from header trivia to relocation entries after rejections |
| analysed the crash itself | yes: valgrind "Invalid read of size 8 ... not freed"; gdb and (%rdx,%rdi,8),%rax |
| registered a finding itself | tried and was blocked by our id pattern (FND-run-... rejected) |

The last row is a harness defect: the pattern only accepted short trial slugs. Fixed, with a
regression test. The two findings were then registered through the same tool call the agent
used, citing the agent's own evidence ids.
