# quarprom —— 隔离目录晋升允许区的权限回执核验（本地安全机制模拟）

仅使用 **原生 Windows + Python 3.12 标准库**，无任何第三方依赖。所有数据均为本地合成的虚构制品。

## 1. 要解决的问题

模拟一次把本地虚构制品从**隔离区（quarantine）**晋升到**允许区（allowed）**的完整安全流程，并系统性地回答题面的每个要求：

| 题面要求 | 实现位置 |
|---|---|
| 审批绑定目标根、完整摘要、代号、两个独立控制人 | `quarprom/approval.py`：双 keyid HMAC-SHA256 分别签名，绑定载荷四要素逐字节参与签名 |
| 来源别名不能偷换控制根 | `quarprom/paths.py`：8.3 展开 + `realpath` + `commonpath` + 根内逐组件重解析点拒绝 + `samefile` 兜底；`mklink /J` 攻击演示 |
| 真实双线程和屏障 | `quarprom/promoter.py`：`gate-controller` 与 `segmented-writer` 两个真实 OS 线程，两个 `threading.Barrier(2)` |
| 撤销先提交 | `quarprom/journal.py`：undo journal 在**任何**允许区变更之前原子落盘并 fsync |
| 最后分段写入失败 | `SegmentedWriter` 每段 fsync，最后一段注入 `SegmentedWriteError`，按 journal 逆序回滚，决定链记 ABORTED |
| 晋升已持久化但回执丢失 | 决定入链/视图发布/文件落地后、写回执前 `os._exit(2)`；子进程真实重启恢复并补建回执 |
| 重启后从实际目录和决定日志判定公开集合 | `quarprom/recovery.py`：物理目录与哈希链决定日志双向对账 |
| 验证器给出最早越权可见证据 | `inspector/checker.py`（**不导入 quarprom**，独立重算）：按时间戳/出生时间排序的 earliest evidence |
| 持续读者持有旧视图时更新下一版，旧视图仍可重放 | `quarprom/views.py` 不可变 CAS 版本 + `quarprom/reader.py` 真实并发读者 |
| 六万条清单：只重核受影响目录 vs 全量 | `quarprom/benchmark.py`：物理树与合成清单双口径，校验增量与全量逐字节一致并给出加速比 |

## 2. 目录结构

```
quarprom/                 晋升程序（生产侧）
  paths.py                Win32 路径/重解析点/8.3 别名防御（ctypes 调 kernel32）
  digest.py               SHA-256 / HMAC / 规范化 JSON
  approval.py             双控制人审批与四要素绑定校验
  declog.py               仅追加哈希链决定日志（JSONL，prev + record_hash）
  journal.py              undo journal + 分段写入器
  views.py                内容寻址存储 + 不可变版本视图 + 目录摘要树
  receipts.py             晋升回执（最后一步持久化）
  promoter.py             双线程 + 双屏障编排与故障注入
  recovery.py             重启对账与公开集合判定
  reader.py               持续读者并发演示
  benchmark.py            6 万条基准
  cli.py                  统一命令行
inspector/                独立事后检查器（与 quarprom 零导入共享，仅共享文件格式）
  checker.py              C1–C8 全量重验，CLI 退出码 0/1/2
tests/                    unittest 套件（含真实子进程 os._exit 重启测试）
run_demo.py               端到端演示（全部子进程驱动）
run_demo.bat              原生 Windows 一键入口
```

## 3. 安全机制设计要点

### 3.1 审批（双控制人 + 四要素绑定）

审批绑定载荷（签名覆盖整个规范化 JSON）：

```json
{
  "version": 1,
  "target_root": "<规范化允许根>",
  "full_digest": "<制品完整 SHA-256，非截断>",
  "codename": "<代号>",
  "source_aliases": ["<全部声明来源别名，规范化后排序>"]
}
```

- 必须有**恰好两个不同 keyid** 的控制人分别 HMAC-SHA256 签名（`controllers.keys.json` 独立密钥）；
- 晋升时重验签名，并把请求与绑定逐项比对：目标根、完整摘要、代号、实际来源；
- 每个声明别名都必须 `os.path.samefile` 解析回**同一物理对象**，否则按别名偷换拒绝。

### 3.2 路径防御（别名不能偷换控制根）

`assert_under_root(root, target)` 三道防线：

1. `GetFullPathNameW` 展开 8.3 短名 → `os.path.realpath` 解析 junction/symlink/mount point → `normcase` 规范化，再 `commonpath` 比较（挡 `..`、短名、大小写、外部 junction）；
2. 受控根内部**逐组件**检测 `FILE_ATTRIBUTE_REPARSE_POINT`——即使解析后仍在根内，根内 junction 别名本身也被拒绝；
3. `os.path.samefile` 兜底，防等价路径/硬链接混淆。

### 3.3 双线程双屏障与崩溃安全

```
闸门线程 G：独立重验审批/摘要/根绑定 ──Barrier1──> 复核暂存摘要 ──Barrier2──> 放行
写入线程 W：(journal 已先提交)        ──Barrier1──> 分段写暂存   ──Barrier2──> 原子落地
```

- **Barrier1**：两线程都确认 undo journal 已 fsync 落盘，才允许任何允许区变更；
- **Barrier2**：暂存文件摘要经闸门线程独立重算通过，才允许 `os.replace` 原子提交；
- 任一线程失败即 `barrier.abort()`，另一线程收到 `BrokenBarrierError` 立即停手；事件无条件 `set()` 防止对端空等；
- undo journal 记录每个逆操作（删文件/删目录/还原备份），回滚按逆序执行。

### 3.4 重启恢复的判定矩阵

| 决定日志最新态 | 允许区实际文件 | 判定 |
|---|---|---|
| PROMOTED，摘要一致 | 在 | 公开；回执缺失则**用决定链事实补建** |
| PROMOTED | 缺失/摘要不符 | `PROMISED_BUT_MISSING` / `DIGEST_MISMATCH` |
| ABORTED | 在 | `ABORTED_BUT_VISIBLE`（最早越权可见，附 abort 时间戳） |
| 无任何决定 | 在 | `UNDECIDED_BUT_VISIBLE`（未授权可见，附文件出生时间） |
| 残留 undo journal | — | 先逆序回滚并写 RECOVERED 记录 |

### 3.5 独立检查器（inspector）

- 与晋升程序**零代码共享**（测试 `test_checker_module_does_not_import_quarprom` 强制该约束），密码学原语、哈希链、Win32 属性检测全部独立重写；
- C1 配置/根 → C2 哈希链 → C3 双签重验 → C4 四要素绑定 → C5 重解析点扫描 → C6 双向对账 → C7 回执 → C8 视图/CAS；
- 输出 `earliest_unauthorized_evidence`：按 `first_visible_ts_ns`（决定时间或文件 `st_birthtime_ns`）取最早的越权可见物证；
- 退出码：`0` 干净 / `1` 发现违规 / `2` 致命（日志断裂等无法完成检查）。

### 3.6 不可变版本视图与持续读者

- 制品进内容寻址存储 `blobs/ab/cd/<sha256>`（硬链接优先、自动去重、内容变则摘要必变）；
- 每版 `views/vN/manifest.json` 不可变，发布只新增目录并原子切换 `current.json`；
- 读者线程持有 vN 引用期间，发布线程并发发布 v(N+1)：旧版全程可重放（逐 blob 重算摘要），无需锁。

### 3.7 六万条基准

- **物理树口径**：真实生成 60000 个文件 / 300 个目录，变异 3 个受影响目录后比较全量 walk+SHA-256 与只重核受影响目录；
- **清单口径**：60000 条确定性合成清单的全量聚合 vs 只聚合受影响条目；
- 正确性闸门：受影响目录上两种口径聚合摘要必须**逐字节一致**，未受影响目录摘要必须与基线相同，否则基准判失败。

## 4. 使用方式（原生 Windows）

一键端到端演示（含真实子进程重启、junction 攻击、6 万条清单基准；约几分钟）：

```bat
run_demo.bat
REM 物理树基准也跑满 6 万文件（约 15~30 分钟，实测数据见 BENCHMARK_RESULTS.md）：
run_demo.bat --full-physical
```

分步 CLI：

```bat
python -m quarprom.cli setup --root demo-out\ws --quarantine demo-out\q --allowed demo-out\a
python -m quarprom.cli make-artifact --workspace demo-out\ws --codename alpha
python -m quarprom.cli approve --workspace demo-out\ws --codename alpha
python -m quarprom.cli promote --workspace demo-out\ws --codename alpha --relpath project/alpha.bin
python -m quarprom.cli promote --workspace demo-out\ws --codename beta  --relpath project/beta.bin --fail-last-segment
python -m quarprom.cli promote --workspace demo-out\ws --codename gamma --relpath project/gamma.bin --crash-before-receipt
python -m quarprom.cli recover --workspace demo-out\ws
python -m quarprom.cli check   --workspace demo-out\ws
python -m quarprom.cli alias-attack --workspace demo-out\ws
python -m quarprom.cli reader-demo  --workspace demo-out\ws
python -m quarprom.cli benchmark   --workspace demo-out\ws --n 60000 --dirs 300
```

测试：

```bat
python -m unittest discover -s tests -v
```

## 5. 演示的成功判据（run_demo.py 内置硬断言）

1. 正常晋升 PROMOTED，回执与视图齐全；
2. 最后一段失败 → ABORTED，journal 回滚后允许区零残留、恢复无违规；
3. `os._exit` 崩溃后新进程恢复：仅依据磁盘即补建 `project/gamma.bin` 回执，独立检查器干净通过；
4. 人工制造两类越权可见后，检查器退出码 1 并给出最早越权证据；
5. junction 逃逸、根内 junction、`..` 遍历三类别名攻击全部拦截；
6. 旧视图在并发发布后重放成功，全部历史版本保留；
7. 6 万条基准两口径结果一致且增量显著快于全量。
