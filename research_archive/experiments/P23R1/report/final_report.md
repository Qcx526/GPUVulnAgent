# trial0 — final report

**Goal.** # 研究任务（盲测）

目标 CVE：CVE-2024-0124
目标组件：NVIDIA CUDA Toolkit 的 nvdisasm

任务：判断这个 CVE 在本机可获取的版本上是否能够真实复现，并给出有证据的结论。

要求：
1. 自己联网查官方公告与 NVD，确认漏洞类型、受影响版本、修复版本；记录你实际访问的 URL。
2. 自己获取受影响版本与修复版本的 nvdisasm。优先 NVIDIA 官方签名 APT 仓库的独立 deb 包；
   必须验证签名链与 SHA256，并用 `nvdisasm --version` 确认版本，不能只看文件名。
3. 自己构造基线输入（可用容器里的 nvcc 生成 cubin），再自己设计并生成 PoC / 变异输入。
   每次变异要有明确假设，说明你想命中哪条路径。
4. 自己编译、执行、观察 stdout/stderr、判断退出状态。只有监督器确认的信号才算崩溃。
5. 在受影响版本和修复版本上跑同样的字节；记录差分。
6. 如果看到与 CVE 描述不一致的异常，用 finding_new 独立登记，不要并入 CVE 结论。
7. 结论必须分层写清：执行过什么、输入是否被接受、是否到达目标路径、是否观察到崩溃、
   是否有版本差分、机制是否成立、是否归因到该 CVE。

环境事实（不是方法建议）：
- Windows 主机 + WSL2 Ubuntu 22.04 + Docker，普通用户可用；GPU 为 GTX 1660（sm_75）。
- 可用镜像 nvidia/cuda:12.8.0-devel-ubuntu22.04（含 nvcc/nvdisasm/cuobjdump；无 python3/curl，
  需要时可用 apt 安装，network 设为 bridge 并以 root 运行）。
- 容器默认 network=none，只挂载 /work。
- 工具目录里可能已有历史版本的 nvdisasm / cuobjdump 二进制，可以用 tool_search / toolchain_lookup 找。
- 预算有限：先把版本搞清楚，再决定是否值得深入构造输入。

约束：不修改 Windows 驱动，不重启系统，不安装需要管理员权限的 Windows 组件。

**Status.** stopped=max_turns, artifacts=1 (document=1), evidence records=105

## Artifacts

| id | type | v | origin | sha256 | path |
|---|---|---|---|---|---|
| `art-c95ea71ecc1d` | document | 1 | generated | `e4548d2053ce952c` | `session/run/workspace/CONCLUSION-CVE-2024-0124.md` |

## Conclusions

# 最终结论 — CVE-2024-0124（nvdisasm，盲测）

## 一句话结论

**在本机可获取的版本上，我复现了一个与 CVE-2024-0124 修复位置对应的、带干净版本差分的真实崩溃；但官方描述的 CWE-416（use-after-free）机制未能证实 —— 我观测到的是越界读（OOB read）形态。因此：崩溃复现成立、差分成立、归因到该 CVE 的机制尚未成立。**

## 分层结论

| 层次 | 结论 | 强度 |
|---|---|---|
| 执行过什么 | 从 NVIDIA 签名 APT 仓库取得受影响版与修复版 nvdisasm，跑 414 个用例 | 已执行，有证据 |
| 输入是否被接受 | 被接受，解析推进到重定位处理阶段才失败 | 有证据 |
| 是否到达目标路径 | 是 —— 落在 12.6U2 实际打补丁的那条代码路径上 | 有证据 |
| 是否观察到崩溃 | 是，SIGSEGV，稳定可重复 | 有证据 |
| 是否有版本差分 | 是，且是"修好了"的正向差分 | 有证据 |
| 机制是否成立 | **否** —— 观测为越界读，非 use-after-free | 证据与公告冲突 |
| 是否归因到该 CVE | **部分** —— 同一路径，机制未证实 | 推测 |

## 有证据的部分

**1. 公告事实（`#12`, `#14`）**
NVIDIA 公告 a_id/5577：nvdisasm，CWE-416 use-after-free，畸形 ELF，CVSS 3.1 3.3 Low，Win+Linux，受影响"至 CUDA 12.6U1 含"，修复 12.6U2。NVD API 一致（CWE-416，cpe `versionEndExcluding 12.6.2`）。实际访问 URL 均记录在案。

**2. 获取链验证（`#39`, `#57`）**
- `gpgv InRelease` → `Good signature from "cudatools <cudatools@nvidia.com>"`，key `EB693B3035CD5710E231E123A4B469963BF863CC`，exit 0
- InRelease 声明的 Packages SHA256 与实际下载一致（`cb9beb6a…`）
- `cuda-nvdisasm-12-6 12.6.68-1` deb SHA256 匹配；`12.6.77-1` 同样匹配
- `--version` 确认为 `V12.6.68`（Build 2024-08-14）与 `V12.6.77`（Build 2024-09-12）
- 附带发现：`cuda-cuobjdump-12-6` 只含 cuobjdump，nvdisasm 在独立包 `cuda-nvdisasm-12-6`

**3. 版本差分（`#75`, `#79`, `#81`）— 核心证据**
输入 `reloc_off_outside`（在合法 nvcc sm_75 `-rdc` cubin 上，仅把一个 Rela 的 r_offset 改为 0x7fffffff；文件长度与全部节头不变）：

- **12.6.68-1（受影响）**：`exit 139`，SIGSEGV，无任何诊断输出
- **12.6.77-1（修复）**：`exit 1`，`fatal : Relocaiton offest outside section size`

4 组 flag（default / `--print-code` / `-ndf` / `--print-life-ranges`）均确定性复现（`#75`）。

**4. 掩蔽对照（`#75`）**
把 r_offset 设为 `section_size + 1`：受影响版**不崩溃**（exit 1，`Code relocators out of bounds for section '.text._Z9indirectkPff'`），修复版仍报新 fatal。说明触发需要"大偏移"而非"仅越界"—— 这是对差分真实性的有效对照，排除了"任何畸形输入都会挂"的解释。

**5. 补丁定位（`#65`）**
修复版 `.text` +208B、`.rodata` +192B；新增字符串 `"Relocaiton offest outside section size"` 与 `"Could not process EIATTR_INDIRECT_BRANCH_TARGETS for the function '%s'."`。即修复内容确为**重定位偏移范围检查** —— 与我触发崩溃的路径吻合。

**6. 独立异常（`#75`, `#84`）**
`reloc_sym_oob`（Rela r_info 符号索引设为 0x0fffffff）在 **12.6.68-1 和 12.6.77-1 上同样 SIGSEGV（exit 139）**。即厂商自己的修复版本仍存在该崩溃。`finding_new` 因 id 格式校验拒绝（`#100`），该异常已改记在 memory 与 `CONCLUSION-CVE-2024-0124.md` 中。

## 推测 / 未证实的部分

**机制不成立（这是最重要的否定结论，`#94`, `#98`）**
- valgrind：`Invalid read of size 8 … Address 0x84a99667 is not stack'd, malloc'd or (recently) free'd`，且 `Access not within mapped region`
- gdb：SIGSEGV 于 `0x40b6be  and (%rdx,%rdi,8),%rax`，即**由文件数据导出的索引做表查找越界**
- 全语料 valgrind 扫描中"提及 freed 内存"的输入数 = **0**

因此这是 **CWE-125 越界读形态**，不是 use-after-free。公告说的"读被释放的内存"这一时序我**没有观测到**。它确实是 12.6U2 修补的那条路径（差分+补丁定位都指向重定位范围检查），但"这是不是公告所述的那个 UAF"仍属推测。也可能公告的 CWE 分类偏宽（NVIDIA 把同一处重定位解析缺陷记为 416），也可能 UAF 在另一条我尚未命中的子路径上——两者我都无法用现有证据区分。

**其他不确定性**
- 二进制为 stripped，调用栈无符号（`#94`）
- `reloc_sym_oob` 是否属于 CVE-2024-0123（CWE-1285）或 -0125（CWE-476）：均不匹配（非 NULL 解引用、非 UAF），当前最贴合 CWE-125，但未定论
- 该异常在 12.8 / 13.0 上是否仍在：**未测**（`#98` 中 awk 引号 bug 导致索引查询失败）

## 环境层面的重要限制（必须记录）

`container_exec` 监督器**从不设置 `signal_verified`**：我用 `kill -SEGV $$` 做的对照实验同样返回 `unverified_signal`、`signal_verified=false`，`signal=""`（`#87`）。也就是说在这套环境里没有任何崩溃能被"监督器确认为信号"——包括人为构造的必然崩溃。因此我的崩溃判定建立在三重独立证据上：`exit 139`、bash 的 `Segmentation fault (core dumped)`（`#89`）、以及 gdb/valgrind 的独立确认（`#94`）。这是工具链缺陷，不是目标行为；但按你的规则，我明确标注：**本报告中的"崩溃"均非监督器确认**。

## 还缺什么条件

1. **能确认信号的监督器**（`signal_verified` 可用的执行通道），才能把"崩溃"升级为规则意义上的 confirmed
2. **符号化的 12.6.68/12.6.77 nvdisasm**（或 IDA/Ghidra 交叉引用 0x40b6be 附近、对照新增的 fatal 字符串）才能判断：修复前这块缓冲区是否曾被释放后再使用 —— 这是澄清 416 vs 125 的唯一途径
3. **定向构造**：围绕 `.nv.info`/`EIATTR_INDIRECT_BRANCH_TARGETS`（修复版另一处新字符串）的用例，我设计了 7 个但在这批 cubin 上均未触发差异，可能是元数据布局不对
4. 补测 `reloc_sym_oob` 在 12.8 / 13.0 上的行为，以确认它是否至今未修

我倾向的判断（推测，非结论）：CVE-2024-0124 就是这条重定位偏移路径，NVIDIA 的 CWE-416 标注可能偏宽；实测行为是越界读导致 DoS，与公告的"limited denial of service"影响一致，但 CWE 分类与我的观测不符。

产物：`CONCLUSION-CVE-2024-0124.md`（`#104`），完整用例矩阵 `results.json`（`#75`），PoC 字节在 trail1 的 `mut/` 下，两个 nvdisasm 二进制及 deb 均在 trail1 manifest 中带 SHA256。
