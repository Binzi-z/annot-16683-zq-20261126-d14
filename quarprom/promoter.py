"""晋升编排：真实双线程 + 双 Barrier，复现两类崩溃。

线程模型（threading.Barrier(2)，两个真实 OS 线程）：
  写入线程 W：提交 undo journal ──屏障1──> 分段写暂存 ──屏障2──> 原子落地允许区
  闸门线程 G：独立复核审批/摘要/根绑定 ──屏障1──> 复核暂存摘要 ──屏障2──> 放行提交
屏障1 保证"撤销先提交"：两个线程都确认 undo journal 已落盘后，才允许改动允许区。
屏障2 保证提交闸门：暂存文件摘要经独立线程复核后才允许原子替换。
任一线程失败都调用 barrier.abort()，另一线程收到 BrokenBarrierError 后立即停手。

故障注入：
  fail_last_segment=True   最后一段分段写入失败 -> 依据已提交 journal 回滚 -> ABORTED
  crash_before_receipt=True 晋升已持久化（决定已入链、视图已发布、文件已落地），
                            但在写回执之前 os._exit，模拟进程被杀、回执丢失
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from . import approval as approval_mod
from . import receipts as receipts_mod
from .declog import DecisionLog, LogRecord
from .digest import sha256_bytes, sha256_file
from .errors import (
    ApprovalError, PromotionError, RootAliasError, SegmentedWriteError,
)
from .journal import JOURNAL_SUFFIX, SegmentedWriter, UndoJournal, rollback
from .paths import (
    assert_under_root, atomic_write, ensure_dir, fsync_dir,
    relative_posix, resolved,
)
from .views import PublishedView, ViewStore, build_manifest, put_blob
from .workspace import Workspace

STAGING_DIR = ".staging"
APPROVALS_DIR = "approvals"


@dataclass
class PromotionRequest:
    codename: str
    source: str                      # 隔离区中的来源路径（或其声明别名）
    relpath: str                     # 允许区内相对路径（正斜杠）
    approval: dict[str, Any]         # 已由双控制人签署的审批记录
    content: bytes                   # 制品字节（与审批摘要必须一致）
    fail_last_segment: bool = False
    crash_before_receipt: bool = False
    segment_size: int = 4096


@dataclass
class PromotionResult:
    status: str                      # PROMOTED / ABORTED / CRASHED_BEFORE_RECEIPT
    codename: str
    relpath: str
    digest: str
    decision: LogRecord | None = None
    view: PublishedView | None = None
    receipt_path: str | None = None
    rollback_report: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    thread_trace: list[str] = field(default_factory=list)


class Promoter:
    def __init__(self, ws: Workspace, keystore: approval_mod.KeyStore,
                 crash_hook: Callable[[int], None] | None = None):
        self.ws = ws
        self.keystore = keystore
        self.log = DecisionLog(ws.log_path)
        self.views = ViewStore(ws.views_dir, ws.blobs_dir)
        self._crash_hook = crash_hook or os._exit
        ensure_dir(os.path.join(ws.root, APPROVALS_DIR))

    # ------------------------------------------------------------ 公开入口
    def promote(self, req: PromotionRequest) -> PromotionResult:
        quarantine_root, allowed_root = self.ws.bound_roots()
        trace: list[str] = []
        result = PromotionResult(
            status="PROMOTED", codename=req.codename, relpath=req.relpath, digest=""
        )

        # 1) 路径防御：来源别名不能偷换控制根
        src_canon = assert_under_root(quarantine_root, req.source, what="来源制品")
        target_final = os.path.join(allowed_root, req.relpath.replace("/", os.sep))
        target_canon = assert_under_root(allowed_root, target_final, what="目标制品")
        staging = os.path.join(allowed_root, STAGING_DIR, req.relpath.replace("/", os.sep) + ".tmp")
        assert_under_root(allowed_root, staging, what="暂存文件")

        # 2) 主线程预校验审批（闸门线程会再独立复核一次）
        binding = approval_mod.verify_approval(req.approval, keystore=self.keystore)
        actual_digest = sha256_file(src_canon)
        approval_mod.check_approval_matches(
            binding, target_root=allowed_root, full_digest=actual_digest,
            codename=req.codename, actual_source=src_canon,
        )
        if sha256_bytes(req.content) != actual_digest:
            raise PromotionError("请求内联内容与磁盘来源摘要不一致，拒绝晋升")
        result.digest = actual_digest

        # 3) 归档审批记录，供独立检查器事后重验
        approval_path = os.path.join(self.ws.root, APPROVALS_DIR, f"{req.codename}.approval.json")
        approval_mod.save_approval(req.approval, approval_path)

        # 4) undo journal 先提交（任何允许区变更之前）
        from .journal import journal_id_for
        jid = journal_id_for(req.codename, req.relpath)
        journal_path = os.path.join(self.ws.journals_dir, jid + JOURNAL_SUFFIX)
        journal = UndoJournal(
            journal_id=jid, path=journal_path, codename=req.codename, relpath=req.relpath
        )
        # 预登记暂存文件与最终文件的逆操作（journal 提交前不允许创建任何目录/文件）
        def record_new_dirs(child_path: str) -> None:
            cur = allowed_root
            rel_parts = os.path.relpath(os.path.dirname(child_path), allowed_root).split(os.sep)
            for part in rel_parts:
                cur = os.path.join(cur, part)
                if not os.path.isdir(cur):
                    journal.record_mkdir(cur)

        record_new_dirs(staging)
        record_new_dirs(target_canon)
        if os.path.exists(target_canon):
            backup = target_canon + ".bak"
            atomic_write(backup, open(target_canon, "rb").read())
            journal.record_replace(target_canon, backup)
        else:
            journal.record_create(target_canon)
        journal.record_create(staging)
        journal.commit()  # <-- 撤销先提交：此处之后崩溃都能完整回滚
        trace.append("W: undo journal committed before any allowed-root mutation")

        # 5) 双线程 + 双屏障执行
        barrier_pre = threading.Barrier(2, timeout=30)
        barrier_commit = threading.Barrier(2, timeout=30)
        shared: dict[str, Any] = {
            "error": None, "staged_digest": None, "gate_ok": False,
            "writer_done": threading.Event(),
        }
        lock = threading.Lock()

        def gate_thread() -> None:
            """独立控制线程：不共享主线程的校验结论，全部重算。"""
            try:
                re_bind = approval_mod.verify_approval(req.approval, keystore=self.keystore)
                re_digest = sha256_file(src_canon)
                approval_mod.check_approval_matches(
                    re_bind, target_root=allowed_root, full_digest=re_digest,
                    codename=req.codename, actual_source=src_canon,
                )
                if resolved(allowed_root) != re_bind["target_root"]:
                    raise RootAliasError("闸门复核：目标根绑定不一致")
                trace.append("G: approval/digest/root-binding independently re-verified")
                barrier_pre.wait()
                # 屏障1 通过后，等待写入线程把暂存段写完
                shared["writer_done"].wait(timeout=30)
                if shared["error"] is not None:
                    raise SegmentedWriteError(shared["error"])
                staged_digest = sha256_file(staging)
                if staged_digest != actual_digest:
                    raise PromotionError(
                        f"闸门复核暂存摘要 {staged_digest} != 审批摘要 {actual_digest}"
                    )
                shared["staged_digest"] = staged_digest
                shared["gate_ok"] = True
                trace.append("G: staged digest re-verified, commit gate released")
                barrier_commit.wait()
            except threading.BrokenBarrierError:
                with lock:
                    if shared["error"] is None:
                        shared["error"] = "闸门线程：屏障被另一线程中止"
            except (ApprovalError, RootAliasError, SegmentedWriteError,
                    PromotionError, OSError) as exc:
                with lock:
                    shared["error"] = f"闸门线程拒绝：{exc}"
                for b in (barrier_pre, barrier_commit):
                    try:
                        b.abort()
                    except threading.BrokenBarrierError:
                        pass

        def writer_thread() -> None:
            try:
                barrier_pre.wait()  # 两线程都确认 journal 已提交，才允许动允许区
                trace.append("W: barrier1 passed, begin segmented staging write")
                writer = SegmentedWriter(
                    staging, segment_size=req.segment_size,
                    fail_on_last=req.fail_last_segment,
                )
                segments = SegmentedWriter.split_segments(req.content, req.segment_size)
                writer.open()
                try:
                    for index, segment in enumerate(segments):
                        writer.write_segment(segment, is_last=index == len(segments) - 1)
                finally:
                    writer.close()
                trace.append(f"W: {writer.bytes_written} bytes staged in {len(segments)} segments")
                shared["writer_done"].set()
                barrier_commit.wait()
                if not shared["gate_ok"]:
                    raise PromotionError("提交屏障通过但闸门未放行，中止")
                # 6) 原子落地允许区
                ensure_dir(os.path.dirname(target_canon))
                os.replace(staging, target_canon)
                fsync_dir(os.path.dirname(target_canon))
                trace.append("W: staged file atomically replaced into allowed root")
            except threading.BrokenBarrierError:
                with lock:
                    if shared["error"] is None:
                        shared["error"] = "写入线程：屏障被另一线程中止"
            except (SegmentedWriteError, PromotionError, OSError) as exc:
                with lock:
                    if shared["error"] is None:
                        shared["error"] = f"写入线程失败：{exc}"
                # 无论成败都必须释放事件，否则闸门线程会卡在 wait 上空等超时
                shared["writer_done"].set()
                for b in (barrier_pre, barrier_commit):
                    try:
                        b.abort()
                    except threading.BrokenBarrierError:
                        pass

        t_gate = threading.Thread(target=gate_thread, name="gate-controller", daemon=True)
        t_write = threading.Thread(target=writer_thread, name="segmented-writer", daemon=True)
        t_gate.start()
        t_write.start()
        t_gate.join()
        t_write.join()
        result.thread_trace = trace

        # 7) 失败路径：journal 回滚 + ABORTED 入链
        if shared["error"] is not None:
            report = rollback(journal_path)
            journal.finish()
            aborted = self.log.append("ABORTED", {
                "codename": req.codename,
                "relpath": req.relpath,
                "digest": actual_digest,
                "target_root": resolved(allowed_root),
                "reason": shared["error"],
                "rollback": report,
            })
            result.status = "ABORTED"
            result.error = shared["error"]
            result.rollback_report = report
            result.decision = aborted
            if os.path.exists(staging):
                os.remove(staging)
            return result

        # 8) 内容寻址入库（不可变 CAS，不纳入 undo 范围：仅通过 manifest 才可见）
        put_blob(self.ws.blobs_dir, target_canon, actual_digest)

        # 9) 发布下一版视图（旧视图保持不可变，读者可继续重放）
        manifest = self._next_manifest(req.relpath, actual_digest, len(req.content))
        published = self.views.publish(manifest)
        self.log.append("VIEW_PUBLISHED", {
            "version": published.version,
            "manifest_digest": manifest["manifest_digest"],
            "relpath": req.relpath,
        })

        # 10) PROMOTED 决定入哈希链（这一步持久化后，晋升即不可抵赖）
        decision = self.log.append("PROMOTED", {
            "codename": req.codename,
            "relpath": req.relpath,
            "digest": actual_digest,
            "target_root": resolved(allowed_root),
            "source": src_canon,
            "approval_digest": approval_mod.approval_digest(req.approval),
            "view_version": published.version,
        })
        result.decision = decision
        result.view = published

        # 11) 回执是最后一步。故障注入：此刻进程直接退出 -> 晋升已持久化、回执丢失
        if req.crash_before_receipt:
            crash_trace = {
                "injected": "crash_before_receipt",
                "codename": req.codename,
                "relpath": req.relpath,
                "digest": actual_digest,
                "decision_hash": decision.record_hash,
                "view_version": published.version,
                "receipt_written": False,
            }
            atomic_write(self.ws.crash_trace_path,
                        json.dumps(crash_trace, sort_keys=True).encode("utf-8"))
            result.status = "CRASHED_BEFORE_RECEIPT"
            journal.finish()
            self._crash_hook(2)  # 默认 os._exit：不跑任何 finally / atexit
            return result

        # 12) 写回执并收尾
        receipt = receipts_mod.build_receipt(
            relpath=req.relpath, codename=req.codename, digest_hex=actual_digest,
            target_root=resolved(allowed_root),
            approval_digest_hex=approval_mod.approval_digest(req.approval),
            decision_hash=decision.record_hash, view_version=published.version,
        )
        result.receipt_path = receipts_mod.write_receipt(self.ws.receipts_dir, receipt)
        journal.finish()
        return result

    # ------------------------------------------------------------ 内部工具
    def _next_manifest(self, relpath: str, digest_hex: str, size: int) -> dict[str, Any]:
        cur = self.views.current_version()
        files: dict[str, Any] = {}
        if cur is not None:
            files = dict(self.views.load_manifest(cur)["files"])
        files[relpath] = {"digest": digest_hex.lower(), "size": size}
        return build_manifest((rel, e["digest"], e["size"]) for rel, e in files.items())
