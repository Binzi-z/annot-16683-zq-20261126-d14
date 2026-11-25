"""命令行编排：建工作区、发审批、晋升、崩溃恢复、别名攻击、读者演示、基准、独立检查。

  python -m quarprom.cli setup ...
  python -m quarprom.cli make-artifact ...
  python -m quarprom.cli approve ...
  python -m quarprom.cli promote [--fail-last-segment|--crash-before-receipt]
  python -m quarprom.cli recover
  python -m quarprom.cli check
  python -m quarprom.cli alias-attack
  python -m quarprom.cli reader-demo
  python -m quarprom.cli benchmark
  python -m quarprom.cli tamper-aborted / tamper-undecided   （供检查器取证演示）
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any

from . import approval as approval_mod
from . import benchmark as bench
from . import reader as reader_mod
from . import receipts as receipts_mod
from .digest import canonical_json, sha256_bytes, sha256_file
from .errors import QuarPromError, RootAliasError
from .paths import (
    assert_under_root, atomic_write, ensure_dir, relative_posix, resolved,
)
from .promoter import PromotionRequest, Promoter
from .recovery import earliest_violation, recover
from .views import build_manifest
from .workspace import Workspace


def _emit(obj: Any) -> None:
    if isinstance(obj, (dict, list)):
        print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))
    else:
        print(obj)


# ---------------------------------------------------------------- 子命令

def cmd_setup(args: argparse.Namespace) -> int:
    ws = Workspace.create(args.root, args.quarantine, args.allowed)
    keystore = approval_mod.KeyStore.create(
        ws.keystore_path, tuple(args.controllers.split(","))
    )
    _emit({
        "workspace": ws.root,
        "quarantine_root": ws.bound_roots()[0],
        "allowed_root": ws.bound_roots()[1],
        "controllers": keystore.keyids(),
        "keystore": ws.keystore_path,
    })
    return 0


def _open(args: argparse.Namespace) -> tuple[Workspace, approval_mod.KeyStore]:
    ws = Workspace.open(args.workspace)
    return ws, approval_mod.KeyStore.load(ws.keystore_path)


def _artifact_path(ws: Workspace, codename: str) -> str:
    return os.path.join(ws.quarantine, f"{codename}.bin")


def cmd_make_artifact(args: argparse.Namespace) -> int:
    ws, _ = _open(args)
    path = _artifact_path(ws, args.codename)
    ensure_dir(os.path.dirname(path))
    payload = (f"fictional artifact {args.codename}\n".encode("utf-8")
               + bytes((i * 13 + 7) & 0xFF for i in range(args.size)))
    atomic_write(path, payload)
    _emit({"codename": args.codename, "source": resolved(path),
           "digest": sha256_file(path), "size": len(payload)})
    return 0


def _read_artifact(ws: Workspace, codename: str) -> tuple[str, bytes, str]:
    path = _artifact_path(ws, codename)
    with open(path, "rb") as fh:
        data = fh.read()
    return path, data, sha256_bytes(data)


def cmd_approve(args: argparse.Namespace) -> int:
    ws, keystore = _open(args)
    q_root, a_root = ws.bound_roots()
    source, _data, digest_hex = _read_artifact(ws, args.codename)
    # 审批绑定：目标根 + 完整摘要 + 代号 + 来源别名（这里把规范来源与一个大小写/分隔符变体一并声明）
    aliases = [source, os.path.abspath(source).lower()]
    signers = tuple(keystore.keyids()[:2])
    ap = approval_mod.issue_approval(
        keystore=keystore, target_root=a_root, full_digest=digest_hex,
        codename=args.codename, source_aliases=aliases, signers=signers,
    )
    out = os.path.join(ws.root, "approvals", f"{args.codename}.approval.json")
    ensure_dir(os.path.dirname(out))
    approval_mod.save_approval(ap, out)
    _emit({"approval": out, "codename": args.codename, "digest": digest_hex,
           "target_root": ap["target_root"], "signers": list(signers),
           "source_aliases": ap["source_aliases"]})
    return 0


def _load_pending_approval(ws: Workspace, codename: str) -> dict[str, Any]:
    path = os.path.join(ws.root, "approvals", f"{codename}.approval.json")
    return approval_mod.load_approval(path)


def cmd_promote(args: argparse.Namespace) -> int:
    ws, keystore = _open(args)
    source, data, digest_hex = _read_artifact(ws, args.codename)
    ap = _load_pending_approval(ws, args.codename)
    req = PromotionRequest(
        codename=args.codename, source=args.source or source,
        relpath=args.relpath, approval=ap, content=data,
        fail_last_segment=args.fail_last_segment,
        crash_before_receipt=args.crash_before_receipt,
        segment_size=args.segment_size,
    )
    promoter = Promoter(ws, keystore)
    try:
        result = promoter.promote(req)
    except RootAliasError as exc:
        _emit({"status": "REJECTED_ROOT_ALIAS", "codename": args.codename, "error": str(exc)})
        return 3
    except QuarPromError as exc:
        _emit({"status": "REJECTED", "codename": args.codename, "error": str(exc)})
        return 4
    out = {
        "status": result.status, "codename": result.codename, "relpath": result.relpath,
        "digest": result.digest, "receipt": result.receipt_path,
        "error": result.error, "rollback": result.rollback_report,
        "view_version": result.view.version if result.view else None,
        "thread_trace": result.thread_trace,
    }
    if result.decision is not None:
        out["decision_seq"] = result.decision.seq
        out["decision_hash"] = result.decision.record_hash
    _emit(out)
    # 注入崩溃时进程已经 os._exit，下面这行只在非崩溃路径到达
    return 0


def cmd_recover(args: argparse.Namespace) -> int:
    ws, _ = _open(args)
    report = recover(ws)
    earliest = earliest_violation(report)
    _emit({
        "recovery_report": report.to_dict(),
        "earliest_violation": None if earliest is None else {
            "code": earliest.code, "relpath": earliest.relpath,
            "detail": earliest.detail,
            "first_visible_ts_ns": earliest.first_visible_ts_ns,
            "evidence": earliest.evidence,
        },
        "public_set_size": len(report.public_set),
    })
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    from inspector.checker import main as checker_main
    argv = ["--workspace", args.workspace]
    if args.json:
        argv += ["--json", args.json]
    return checker_main(argv)


def _make_junction(link: str, target: str) -> str:
    """原生 Windows junction：cmd /c mklink /J（无需开发者模式/管理员权限，同机目录即可）。"""
    ensure_dir(os.path.dirname(link))
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        ["cmd", "/c", "mklink", "/J", link, target],
        capture_output=True, text=True, shell=False,
        encoding="utf-8", errors="replace", env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"mklink /J 失败：{(proc.stderr or proc.stdout or '').strip()}")
    return link


def cmd_alias_attack(args: argparse.Namespace) -> int:
    """两类别名偷换尝试，都必须被路径防御拒绝。"""
    ws, keystore = _open(args)
    q_root, _a_root = ws.bound_roots()
    results: list[dict[str, Any]] = []

    # 攻击 1：junction 指向控制根之外的目录，试图把外部文件伪装成隔离区来源
    outside = os.path.join(ws.root, "outside-stash")
    ensure_dir(outside)
    stolen = os.path.join(outside, "stolen-secret.bin")
    atomic_write(stolen, b"external content that never entered quarantine\n")
    link1 = os.path.join(q_root, "evil_junction")
    if os.path.exists(link1):
        subprocess.run(["cmd", "/c", "rmdir", link1], capture_output=True)
    _make_junction(link1, outside)
    evil_source = os.path.join(link1, "stolen-secret.bin")
    try:
        assert_under_root(q_root, evil_source, what="攻击来源")
        results.append({"attack": "junction-escape", "blocked": False})
    except RootAliasError as exc:
        results.append({"attack": "junction-escape", "blocked": True,
                        "alias": evil_source, "resolved": resolved(evil_source),
                        "reason": str(exc)})

    # 攻击 2：控制根内部 junction 指向根内另一目录（realpath 仍在根内，但别名必须被拒绝）
    real_dir = os.path.join(q_root, "real_dir")
    ensure_dir(real_dir)
    inner = os.path.join(real_dir, "inner.bin")
    atomic_write(inner, b"inner artifact\n")
    link2 = os.path.join(q_root, "inner_alias")
    if os.path.exists(link2):
        subprocess.run(["cmd", "/c", "rmdir", link2], capture_output=True)
    _make_junction(link2, real_dir)
    alias_source = os.path.join(link2, "inner.bin")
    try:
        assert_under_root(q_root, alias_source, what="根内别名来源")
        results.append({"attack": "inside-root-junction", "blocked": False})
    except RootAliasError as exc:
        results.append({"attack": "inside-root-junction", "blocked": True,
                        "alias": alias_source, "resolved": resolved(alias_source),
                        "reason": str(exc)})

    # 攻击 3：词汇遍历 .. 试图跳出控制根
    traversal = os.path.join(q_root, "..", "outside-stash", "stolen-secret.bin")
    try:
        assert_under_root(q_root, traversal, what="遍历别名来源")
        results.append({"attack": "dotdot-traversal", "blocked": False})
    except RootAliasError as exc:
        results.append({"attack": "dotdot-traversal", "blocked": True,
                        "alias": traversal, "resolved": resolved(traversal),
                        "reason": str(exc)})

    _emit({"all_blocked": all(r["blocked"] for r in results), "attacks": results})
    # 清理演示 junction（rmdir 只移除链接本身，不影响目标目录）
    for link in (link1, link2):
        if os.path.lexists(link):
            subprocess.run(["cmd", "/c", "rmdir", link], capture_output=True)
    return 0 if all(r["blocked"] for r in results) else 5


def cmd_reader_demo(args: argparse.Namespace) -> int:
    ws, _ = _open(args)
    from .views import ViewStore, put_blob
    store = ViewStore(ws.views_dir, ws.blobs_dir)
    cur = store.current_version()
    if cur is None:
        raise QuarPromError("尚无任何已发布视图，请先完成至少一次晋升")
    base = store.load_manifest(cur)
    files = dict(base["files"])
    # 新视图引用的内容必须先进入内容寻址存储，否则旧/新视图重放都会判定块缺失
    next_payload = b"next-version-content"
    next_digest = sha256_bytes(next_payload)
    tmp_blob = os.path.join(ws.root, ".reader-demo.tmp")
    atomic_write(tmp_blob, next_payload)
    put_blob(ws.blobs_dir, tmp_blob, next_digest)
    os.remove(tmp_blob)
    files["demo/next-version.bin"] = {"digest": next_digest, "size": len(next_payload)}
    manifest = build_manifest((rel, e["digest"], e["size"]) for rel, e in files.items())
    observed = reader_mod.concurrent_publish_with_stale_reader(store, next_manifest=manifest)
    _emit(observed)
    return 0 if observed["old_replay_ok"] and observed["old_version_still_exists"] else 6


def cmd_tamper_aborted(args: argparse.Namespace) -> int:
    """把一个已 ABORTED 的 relpath 重新写回允许区，制造"最早越权可见"证据。"""
    ws, _ = _open(args)
    _q, a_root = ws.bound_roots()
    target = os.path.join(a_root, args.relpath.replace("/", os.sep))
    ensure_dir(os.path.dirname(target))
    atomic_write(target, b"re-created after abort without any promotion decision\n")
    _emit({"tampered": target, "relpath": args.relpath})
    return 0


def cmd_tamper_undecided(args: argparse.Namespace) -> int:
    """向允许区投放一个决定日志里完全不存在的文件（未授权可见）。"""
    ws, _ = _open(args)
    _q, a_root = ws.bound_roots()
    target = os.path.join(a_root, args.relpath.replace("/", os.sep))
    ensure_dir(os.path.dirname(target))
    atomic_write(target, b"ghost file with no decision record\n")
    _emit({"tampered": target, "relpath": args.relpath})
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    ws, _ = _open(args)
    tree_root = os.path.join(ws.root, "bench-tree")
    ensure_dir(tree_root)
    affected = ["d0000", "d0007", "d0123"]
    # 物理口径：先生成、再变异受影响目录，然后比较
    bench.generate_synthetic_tree(tree_root, n=args.n, dirs=args.dirs)
    changed = bench.mutate_physical(tree_root, affected, n=args.n, dirs=args.dirs)
    r_phys = bench.benchmark_physical(tree_root, affected, n=args.n, dirs=args.dirs)
    r_man = bench.benchmark_manifest(n=args.n, dirs=args.dirs, affected_dirs=affected)
    _emit({
        "n": args.n, "dirs": args.dirs,
        "mutated_files": changed,
        "physical_tree": r_phys.to_dict(),
        "synthetic_manifest": r_man.to_dict(),
    })
    if not (r_phys.consistent and r_man.consistent):
        return 7
    return 0


def cmd_benchmark_manifest(args: argparse.Namespace) -> int:
    """仅清单口径：不落盘，n 条合成清单的全量聚合 vs 受影响目录聚合。"""
    r_man = bench.benchmark_manifest(n=args.n, dirs=args.dirs,
                                     affected_dirs=["d0000", "d0007", "d0123"])
    _emit({"n": args.n, "dirs": args.dirs, "synthetic_manifest": r_man.to_dict()})
    return 0 if r_man.consistent else 7


# ---------------------------------------------------------------- 入口

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="quarprom", description="隔离区晋升允许区安全机制模拟")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("setup", help="创建工作区与双控制人密钥库")
    s.add_argument("--root", required=True)
    s.add_argument("--quarantine", required=True)
    s.add_argument("--allowed", required=True)
    s.add_argument("--controllers", default="alice,bob")
    s.set_defaults(func=cmd_setup)

    s = sub.add_parser("make-artifact", help="在隔离区生成本地虚构制品")
    s.add_argument("--workspace", required=True)
    s.add_argument("--codename", required=True)
    s.add_argument("--size", type=int, default=4096)
    s.set_defaults(func=cmd_make_artifact)

    s = sub.add_parser("approve", help="双控制人审批（绑定根/摘要/代号/来源别名）")
    s.add_argument("--workspace", required=True)
    s.add_argument("--codename", required=True)
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("promote", help="执行双线程屏障晋升")
    s.add_argument("--workspace", required=True)
    s.add_argument("--codename", required=True)
    s.add_argument("--relpath", required=True)
    s.add_argument("--source", default=None, help="覆盖来源路径（别名攻击演示用）")
    s.add_argument("--fail-last-segment", action="store_true")
    s.add_argument("--crash-before-receipt", action="store_true")
    s.add_argument("--segment-size", type=int, default=4096)
    s.set_defaults(func=cmd_promote)

    s = sub.add_parser("recover", help="重启恢复：实际目录与决定日志对账")
    s.add_argument("--workspace", required=True)
    s.set_defaults(func=cmd_recover)

    s = sub.add_parser("check", help="运行独立事后检查器")
    s.add_argument("--workspace", required=True)
    s.add_argument("--json", default=None)
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("alias-attack", help="原生 junction/遍历别名偷换攻击演示")
    s.add_argument("--workspace", required=True)
    s.set_defaults(func=cmd_alias_attack)

    s = sub.add_parser("reader-demo", help="持续读者持有旧视图并发发布下一版")
    s.add_argument("--workspace", required=True)
    s.set_defaults(func=cmd_reader_demo)

    s = sub.add_parser("tamper-aborted", help="投放已撤销事务的制品（取证演示）")
    s.add_argument("--workspace", required=True)
    s.add_argument("--relpath", required=True)
    s.set_defaults(func=cmd_tamper_aborted)

    s = sub.add_parser("tamper-undecided", help="投放无决定记录的文件（取证演示）")
    s.add_argument("--workspace", required=True)
    s.add_argument("--relpath", required=True)
    s.set_defaults(func=cmd_tamper_undecided)

    s = sub.add_parser("benchmark", help="6 万条合成清单基准：增量重核 vs 全量（含物理树）")
    s.add_argument("--workspace", required=True)
    s.add_argument("--n", type=int, default=60_000)
    s.add_argument("--dirs", type=int, default=300)
    s.set_defaults(func=cmd_benchmark)

    s = sub.add_parser("benchmark-manifest", help="仅清单口径基准（不落盘，可跑满 6 万条）")
    s.add_argument("--workspace", required=True)
    s.add_argument("--n", type=int, default=60_000)
    s.add_argument("--dirs", type=int, default=300)
    s.set_defaults(func=cmd_benchmark_manifest)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
