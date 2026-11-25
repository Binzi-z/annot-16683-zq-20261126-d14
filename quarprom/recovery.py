"""重启恢复：从"实际目录"和"决定日志"两个独立事实源对账，判定公开集合。

判定矩阵（按 relpath 折叠决定日志的最新记录，对照允许区实际文件）：
  日志最新=PROMOTED 且文件在、摘要一致      -> 公开；缺回执则补回执（晋升已持久化、回执丢失）
  日志最新=PROMOTED 但文件缺失/摘要不符      -> 违规：持久化承诺与磁盘不符
  日志最新=ABORTED  但文件在                -> 违规：已撤销事务的制品仍可见（最早越权可见）
  无任何决定       但文件在                  -> 违规：未授权制品出现在允许区
  存在残留 undo journal                      -> 先按 journal 回滚，再进入对账
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any

from . import receipts as receipts_mod
from .declog import DecisionLog
from .digest import sha256_file
from .journal import list_journals, rollback
from .paths import atomic_write, relative_posix, resolved
from .workspace import Workspace

STAGING_DIR = ".staging"


@dataclass
class PublicEntry:
    relpath: str
    digest: str
    size: int
    source_of_truth: str          # log+disk / receipt-rebuilt
    receipt_rebuilt: bool = False


@dataclass
class Violation:
    code: str
    relpath: str | None
    detail: str
    first_visible_ts_ns: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class RecoveryReport:
    quarantine_root: str
    allowed_root: str
    journals_rolled_back: list[dict[str, Any]]
    public_set: list[PublicEntry]
    violations: list[Violation]
    rebuilt_receipts: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "quarantine_root": self.quarantine_root,
            "allowed_root": self.allowed_root,
            "journals_rolled_back": self.journals_rolled_back,
            "public_set": [asdict(e) for e in sorted(self.public_set, key=lambda e: e.relpath)],
            "violations": [asdict(v) for v in self.violations],
            "rebuilt_receipts": self.rebuilt_receipts,
        }


def _physical_files(allowed_root: str) -> dict[str, str]:
    """实际目录事实源：relpath -> 实际摘要（排除暂存区与内部文件）。"""
    found: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(allowed_root):
        # 不跟随重解析点；遇到直接从遍历中剔除并交由检查器告警
        dirnames[:] = [d for d in dirnames if d != STAGING_DIR]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = relative_posix(allowed_root, full)
            if rel.startswith(STAGING_DIR + "/"):
                continue
            found[rel] = sha256_file(full)
    return found


def recover(ws: Workspace) -> RecoveryReport:
    quarantine_root, allowed_root = ws.bound_roots()
    log = DecisionLog(ws.log_path)
    records = log.verify_chain()  # 哈希链必须完整，否则直接抛出 LogIntegrityError

    # 1) 残留 undo journal：崩溃在回滚前 -> 先回滚
    rolled_back: list[dict[str, Any]] = []
    for jp in list_journals(ws.journals_dir):
        report = rollback(jp)
        os.remove(jp)
        rolled_back.append({"journal": jp, "actions": report})
        log.append("RECOVERED", {"journal": jp, "rollback": report, "reason": "leftover-journal"})

    # 2) 折叠每个 relpath 的最新"决定"（只认 PROMOTED/ABORTED；
    # VIEW_PUBLISHED/RECOVERED 是事件记录，不能覆盖晋升/撤销决定），
    # 并保留最早 ABORTED 时间作为越权可见下界
    latest: dict[str, Any] = {}
    first_abort_ts: dict[str, int] = {}
    for rec in records:
        if rec.kind not in ("PROMOTED", "ABORTED"):
            continue
        rel = rec.payload.get("relpath")
        if rel is None:
            continue
        latest[rel] = rec
        if rec.kind == "ABORTED" and rel not in first_abort_ts:
            first_abort_ts[rel] = rec.ts_ns

    physical = _physical_files(allowed_root)
    public: list[PublicEntry] = []
    violations: list[Violation] = []
    rebuilt: list[str] = []

    # 3) 以日志为主线对账
    for rel, rec in sorted(latest.items()):
        on_disk = rel in physical
        if rec.kind == "PROMOTED":
            expected_digest = rec.payload["digest"]
            if not on_disk:
                violations.append(Violation(
                    code="PROMISED_BUT_MISSING", relpath=rel,
                    detail="决定日志记录 PROMOTED 但允许区实际文件缺失",
                    first_visible_ts_ns=rec.ts_ns,
                    evidence={"decision_seq": rec.seq, "decision_hash": rec.record_hash},
                ))
                continue
            actual_digest = physical[rel]
            if actual_digest != expected_digest:
                violations.append(Violation(
                    code="DIGEST_MISMATCH", relpath=rel,
                    detail=f"磁盘摘要 {actual_digest} 与晋升决定 {expected_digest} 不符",
                    first_visible_ts_ns=rec.ts_ns,
                    evidence={"decision_seq": rec.seq, "expected": expected_digest,
                              "actual": actual_digest},
                ))
                continue
            entry = PublicEntry(
                relpath=rel, digest=actual_digest,
                size=os.path.getsize(os.path.join(allowed_root, rel.replace("/", os.sep))),
                source_of_truth="decision-log+physical-dir",
            )
            # 晋升已持久化但回执丢失：用决定链中的事实重建回执
            if not receipts_mod.receipt_exists(ws.receipts_dir, rel):
                receipt = receipts_mod.build_receipt(
                    relpath=rel, codename=rec.payload["codename"],
                    digest_hex=actual_digest, target_root=rec.payload["target_root"],
                    approval_digest_hex=rec.payload.get("approval_digest", ""),
                    decision_hash=rec.record_hash,
                    view_version=rec.payload.get("view_version", 0),
                )
                receipts_mod.write_receipt(ws.receipts_dir, receipt)
                rebuilt.append(rel)
                entry.receipt_rebuilt = True
                entry.source_of_truth = "decision-log+physical-dir(receipt rebuilt)"
                log.append("RECOVERED", {
                    "relpath": rel, "reason": "receipt-missing-after-durable-promotion",
                })
            public.append(entry)
        elif rec.kind == "ABORTED":
            if on_disk:
                violations.append(Violation(
                    code="ABORTED_BUT_VISIBLE", relpath=rel,
                    detail="事务已 ABORTED 并完成回滚记录，但制品仍出现在允许区（最早越权可见）",
                    first_visible_ts_ns=first_abort_ts.get(rel, rec.ts_ns),
                    evidence={
                        "abort_seq": rec.seq, "abort_ts_ns": rec.ts_ns,
                        "actual_digest": physical[rel],
                        "abort_reason": rec.payload.get("reason"),
                    },
                ))

    # 4) 以实际目录为主线：抓"无任何决定"的未授权文件
    decided = set(latest)
    for rel, actual_digest in sorted(physical.items()):
        if rel in decided:
            continue
        violations.append(Violation(
            code="UNDECIDED_BUT_VISIBLE", relpath=rel,
            detail="允许区出现决定日志中没有任何晋升记录的文件（未授权可见）",
            first_visible_ts_ns=None,
            evidence={"actual_digest": actual_digest},
        ))

    report = RecoveryReport(
        quarantine_root=quarantine_root, allowed_root=allowed_root,
        journals_rolled_back=rolled_back, public_set=public,
        violations=violations, rebuilt_receipts=rebuilt,
    )
    atomic_write(ws.recovery_report_path, json.dumps(
        report.to_dict(), sort_keys=True, ensure_ascii=False, indent=2).encode("utf-8"))
    return report


def earliest_violation(report: RecoveryReport) -> Violation | None:
    """验证器/恢复共用：取最早越权可见证据（无时间戳的排最后）。"""
    if not report.violations:
        return None
    return sorted(
        report.violations,
        key=lambda v: (v.first_visible_ts_ns is None, v.first_visible_ts_ns or 0),
    )[0]
