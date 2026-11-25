"""端到端演示编排：用子进程真实复现"进程死亡 + 重启"，不做任何进程内模拟。

流程：
  0. 建工作区、两个虚构制品、双控制人审批
  1. 正常晋升（回执完整）
  2. 故障 A：最后一段分段写入失败 -> ABORTED + journal 回滚，重启检查确认无残留
  3. 故障 B：晋升已持久化但回执丢失 -> 子进程 os._exit -> 新子进程恢复并补回执
  4. 独立检查器：制造两类越权可见状态并取证（最早越权证据）
  5. 原生 Windows junction / 根内 junction / .. 别名攻击全部被拒
  6. 持续读者持有旧视图，并发发布下一版，旧视图重放通过
  7. 六万条合成清单：增量重核 vs 全量计算（正确性 + 耗时 + 加速比）
所有阶段产出写入 demo-out/ 并在结尾打印汇总。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
OUT = os.path.join(HERE, "demo-out")


def run(label: str, *argv: str, expect_rc: int = 0, cwd: str | None = None) -> dict:
    """以子进程运行 CLI，捕获 stdout JSON。崩溃注入用例允许非零退出。"""
    env = dict(os.environ)
    # 强制子进程 Python 以 UTF-8 输出，规避中文 Windows 默认 cp936 导致的解码失败
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run([PY, "-m", *argv], capture_output=True, text=True,
                          cwd=cwd or HERE, encoding="utf-8", errors="replace", env=env)
    entry = {"label": label, "argv": list(argv), "returncode": proc.returncode,
             "stdout": (proc.stdout or "").strip(),
             "stderr": (proc.stderr or "").strip()}
    try:
        entry["json"] = json.loads(proc.stdout)
    except json.JSONDecodeError:
        entry["json"] = None
    if proc.returncode != expect_rc:
        entry["unexpected_returncode"] = True
    return entry


def main(physical_n: int = 60_000, manifest_n: int = 60_000) -> int:
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)

    ws = os.path.join(OUT, "workspace")
    # 控制根直接采用工作区内部的两个独立目录，保证 setup 绑定根与制品实际位置一致
    qdir = os.path.join(ws, "quarantine")
    adir = os.path.join(ws, "allowed")
    report: list[dict] = []

    # 0) 初始化
    report.append(run("0.setup", "quarprom.cli", "setup",
                      "--root", ws, "--quarantine", qdir, "--allowed", adir))
    for code in ("alpha", "beta", "gamma"):
        report.append(run(f"0.make.{code}", "quarprom.cli", "make-artifact",
                          "--workspace", ws, "--codename", code))
        report.append(run(f"0.approve.{code}", "quarprom.cli", "approve",
                          "--workspace", ws, "--codename", code))

    # 1) 正常晋升
    report.append(run("1.promote-ok", "quarprom.cli", "promote",
                      "--workspace", ws, "--codename", "alpha",
                      "--relpath", "project/alpha.bin"))

    # 2) 故障 A：最后一段写入失败（本进程内可捕获，ABORTED + 回滚）
    report.append(run("2.fail-last-segment", "quarprom.cli", "promote",
                      "--workspace", ws, "--codename", "beta",
                      "--relpath", "project/beta.bin",
                      "--fail-last-segment", "--segment-size", "512"))
    report.append(run("2.recover-after-abort", "quarprom.cli", "recover",
                      "--workspace", ws))

    # 3) 故障 B：os._exit 真实进程死亡，独立子进程重启恢复（回执丢失 -> 重建）
    crashed = run("3.crash-before-receipt", "quarprom.cli", "promote",
                  "--workspace", ws, "--codename", "gamma",
                  "--relpath", "project/gamma.bin",
                  "--crash-before-receipt", expect_rc=2)
    report.append(crashed)
    report.append(run("3.recover-after-restart", "quarprom.cli", "recover",
                      "--workspace", ws))
    report.append(run("3.checker-after-recovery", "quarprom.cli", "check",
                      "--workspace", ws,
                      "--json", os.path.join(OUT, "check-clean.json")))

    # 4) 越权取证：已撤销制品重现 + 无决定记录的幽灵文件
    report.append(run("4.tamper-aborted", "quarprom.cli", "tamper-aborted",
                      "--workspace", ws, "--relpath", "project/beta.bin"))
    report.append(run("4.tamper-ghost", "quarprom.cli", "tamper-undecided",
                      "--workspace", ws, "--relpath", "shadow/ghost.bin"))
    report.append(run("4.checker-evidence", "quarprom.cli", "check",
                      "--workspace", ws,
                      "--json", os.path.join(OUT, "check-evidence.json"),
                      expect_rc=1))

    # 5) 原生 Windows 别名攻击
    report.append(run("5.alias-attack", "quarprom.cli", "alias-attack",
                      "--workspace", ws))

    # 6) 持续读者旧视图重放
    report.append(run("6.reader-demo", "quarprom.cli", "reader-demo",
                      "--workspace", ws))

    # 7) 基准（物理树 + 合成清单两口径；规模可参数化，清单口径默认跑满 6 万）
    t0 = time.perf_counter()
    bench_argv = ["quarprom.cli", "benchmark", "--workspace", ws,
                  "--n", str(physical_n), "--dirs", "300"]
    report.append(run("7.benchmark-60000", *bench_argv))
    bench_wall = time.perf_counter() - t0
    report[-1]["benchmark_wall_seconds"] = round(bench_wall, 3)
    # 清单口径单独跑满 6 万条（无磁盘 IO，开销很小），通过追加一个独立步骤体现
    if manifest_n != physical_n:
        report.append(run("7b.benchmark-manifest-60000",
                          "quarprom.cli", "benchmark-manifest",
                          "--workspace", ws, "--n", str(manifest_n), "--dirs", "300"))

    with open(os.path.join(OUT, "demo-report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    # ---------------- 汇总打印 ----------------
    def j(label: str) -> dict:
        for entry in report:
            if entry["label"] == label:
                return entry["json"] or {}
        return {}

    print("=" * 78)
    print("quarprom 端到端演示汇总（真实子进程重启 / 原生 Windows / 仅标准库）")
    print("=" * 78)

    ok = j("1.promote-ok")
    print(f"[1] 正常晋升: status={ok.get('status')} view=v{ok.get('view_version')} "
          f"决定序号={ok.get('decision_seq')} 回执={'有' if ok.get('receipt') else '无'}")
    for line in ok.get("thread_trace", []):
        print(f"      {line}")

    ab = j("2.fail-last-segment")
    rec = j("2.recover-after-abort")
    print(f"[2] 最后一段写入失败: status={ab.get('status')}")
    print(f"      错误: {ab.get('error')}")
    print(f"      journal 回滚动作: {[r['op'] + ':' + r['result'] for r in ab.get('rollback', [])]}")
    print(f"      重启后公开集合大小={len(rec['recovery_report']['public_set'])}，"
          f"违规数={len(rec['recovery_report']['violations'])}（应为 0）")

    crash = j("3.crash-before-receipt")
    rec3 = j("3.recover-after-restart")
    crash_rc = next(e for e in report if e["label"] == "3.crash-before-receipt")["returncode"]
    print(f"[3] 晋升持久化但回执丢失: 子进程退出码={crash_rc} "
          f"stdout={'(进程已 os._exit，无输出)' if not crash else crash}")
    rebuilt = rec3["recovery_report"]["rebuilt_receipts"]
    print(f"      重启恢复: 补建回执={rebuilt}，公开集合大小={len(rec3['recovery_report']['public_set'])}")
    check_clean = j("3.checker-after-recovery")
    print(f"      独立检查器: ok={check_clean.get('ok')} 发现项={len(check_clean.get('findings', []))}")

    ev = j("4.checker-evidence")
    print(f"[4] 越权取证: 检查器退出码=1，发现 {len(ev.get('findings', []))} 项")
    earliest = ev.get("earliest_unauthorized_evidence")
    if earliest:
        print(f"      最早越权可见证据: [{earliest['code']}] {earliest['relpath']}")
        print(f"        first_visible_ts_ns={earliest['first_visible_ts_ns']}")
        print(f"        message={earliest['message']}")
        print(f"        evidence={json.dumps(earliest['evidence'], ensure_ascii=False)}")

    atk = j("5.alias-attack")
    print(f"[5] 别名攻击: 全部拦截={atk.get('all_blocked')}")
    for a in atk.get("attacks", []):
        print(f"      {a['attack']}: blocked={a['blocked']} -> {a.get('reason', '')[:96]}")

    rd = j("6.reader-demo")
    print(f"[6] 持续读者: 持有 v{rd.get('reader_held_version')}（{rd.get('old_replay_files')} 个文件），"
          f"并发发布 v{rd.get('published_version')}，旧视图重放={rd.get('old_replay_ok')}，"
          f"全部版本={rd.get('all_versions')}")

    bm = j("7.benchmark-60000")
    for key in ("physical_tree", "synthetic_manifest"):
        b = bm.get(key, {})
        print(f"[7] {key}: {b.get('total_files')} 文件 / {b.get('total_dirs')} 目录，"
              f"受影响 {b.get('affected_dirs')} 目录（{b.get('affected_digest_count')} 次摘要）")
        print(f"      全量={b.get('full_seconds')}s  增量={b.get('affected_seconds')}s  "
              f"加速比={b.get('speedup')}x  结果一致={b.get('consistent')}")
    bm_full = j("7b.benchmark-manifest-60000")
    if bm_full:
        b = bm_full.get("synthetic_manifest", {})
        print(f"[7b] 六万条清单口径: {b.get('total_files')} 条 / {b.get('total_dirs')} 目录，"
              f"全量={b.get('full_seconds')}s 增量={b.get('affected_seconds')}s "
              f"加速比={b.get('speedup')}x 一致={b.get('consistent')}")

    print("=" * 78)
    print(f"完整子进程报告: {os.path.join(OUT, 'demo-report.json')}")
    print(f"检查器证据报告: {os.path.join(OUT, 'check-evidence.json')}")

    # 硬性成功条件
    manifest_ok = (
        bm.get("synthetic_manifest", {}).get("consistent")
        and bm.get("physical_tree", {}).get("consistent")
        and (not bm_full or bm_full.get("synthetic_manifest", {}).get("consistent"))
    )
    success = (
        ok.get("status") == "PROMOTED"
        and ab.get("status") == "ABORTED"
        and len(rec["recovery_report"]["violations"]) == 0
        and rebuilt == ["project/gamma.bin"]
        and check_clean.get("ok") is True
        and earliest is not None
        and atk.get("all_blocked") is True
        and rd.get("old_replay_ok") is True
        and manifest_ok
    )
    print("演示结果:", "全部通过 [PASS]" if success else "存在失败项 [FAIL]")
    return 0 if success else 1


if __name__ == "__main__":
    # 默认物理树用 6000 条控制时长，清单口径始终跑满 6 万；
    # 传入 --full-physical 时物理树也跑满 6 万（本机约 15~30 分钟）。
    full_physical = "--full-physical" in sys.argv
    sys.exit(main(physical_n=60_000 if full_physical else 6_000, manifest_n=60_000))
