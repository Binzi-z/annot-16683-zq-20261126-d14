"""撤销日志（undo journal）与分段写入器。

崩溃安全的关键顺序：
  1. 任何对允许区的变更发生之前，undo journal 先完整落盘并 fsync（"撤销先提交"）；
  2. 之后才执行分段写入，journal 里记录每一步的逆操作；
  3. 全部成功后追加 PROMOTED 决定、发布视图、原子写回执，最后删除 journal。
重启恢复时只要 journal 存在，就按记录逆序回滚，把磁盘恢复到"本次晋升从未开始"的状态。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from .digest import canonical_json, digest_json
from .errors import SegmentedWriteError
from .paths import atomic_write, ensure_dir, fsync_dir

JOURNAL_SUFFIX = ".undo.json"


@dataclass
class UndoJournal:
    journal_id: str
    path: str
    codename: str
    relpath: str
    actions: list[dict[str, Any]] = field(default_factory=list)
    committed: bool = False

    def record_create(self, created_path: str) -> None:
        self.actions.append({"op": "delete", "path": created_path})

    def record_hardlink(self, link_path: str) -> None:
        self.actions.append({"op": "delete", "path": link_path})

    def record_replace(self, replaced_path: str, backup_path: str) -> None:
        self.actions.append({"op": "replace_back", "path": replaced_path, "backup": backup_path})

    def record_mkdir(self, dir_path: str) -> None:
        self.actions.append({"op": "rmdir", "path": dir_path})

    def commit(self) -> None:
        """在任何允许区变更之前调用：journal 原子落盘，此后崩溃都可回滚。"""
        payload = {
            "journal_id": self.journal_id,
            "codename": self.codename,
            "relpath": self.relpath,
            "actions": self.actions,
            "state": "committed",
        }
        atomic_write(self.path, canonical_json(payload))
        self.committed = True

    def append_action(self) -> None:
        """动作发生后把最新逆操作清单刷入已提交 journal（保持 journal 与磁盘同步）。"""
        if not self.committed:
            raise SegmentedWriteError("journal 尚未提交，不允许先改磁盘")
        payload = {
            "journal_id": self.journal_id,
            "codename": self.codename,
            "relpath": self.relpath,
            "actions": self.actions,
            "state": "committed",
        }
        atomic_write(self.path, canonical_json(payload))

    def finish(self) -> None:
        os.remove(self.path)
        fsync_dir(os.path.dirname(self.path))


def load_journal(path: str) -> dict[str, Any]:
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def rollback(journal_path: str) -> list[dict[str, Any]]:
    """按 journal 逆序执行全部逆操作，返回执行报告。"""
    data = load_journal(journal_path)
    report = []
    for action in reversed(data["actions"]):
        op = action["op"]
        p = action["path"]
        if op == "delete":
            if os.path.lexists(p):
                os.remove(p)
                report.append({"op": op, "path": p, "result": "deleted"})
            else:
                report.append({"op": op, "path": p, "result": "already_absent"})
        elif op == "rmdir":
            if os.path.isdir(p):
                try:
                    os.rmdir(p)
                    report.append({"op": op, "path": p, "result": "removed"})
                except OSError as exc:
                    report.append({"op": op, "path": p, "result": f"kept:{exc}"})
        elif op == "replace_back":
            backup = action["backup"]
            if os.path.exists(backup):
                atomic_write(p, open(backup, "rb").read())
                os.remove(backup)
                report.append({"op": op, "path": p, "result": "restored"})
        else:
            report.append({"op": op, "path": p, "result": "unknown_op_skipped"})
    fsync_dir(os.path.dirname(journal_path))
    return report


def list_journals(journals_dir: str) -> list[str]:
    if not os.path.isdir(journals_dir):
        return []
    return sorted(
        os.path.join(journals_dir, n)
        for n in os.listdir(journals_dir)
        if n.endswith(JOURNAL_SUFFIX)
    )


class SegmentedWriter:
    """把一个字节流切成多段写入临时文件，可在最后一段注入故障。

    每段写完即 flush+fsync；fail_on_last=True 时最后一段抛 SegmentedWriteError，
    临时文件保留在磁盘上，由上层依据已提交的 undo journal 回滚。
    支持两种用法：write_all 一次写完，或 open/segments/写段/close 由外部逐段编排。
    """

    def __init__(self, tmp_path: str, segment_size: int = 4096, fail_on_last: bool = False):
        self.tmp_path = tmp_path
        self.segment_size = segment_size
        self.fail_on_last = fail_on_last
        ensure_dir(os.path.dirname(tmp_path))
        self._fh: Any = None
        self._written = 0

    @property
    def bytes_written(self) -> int:
        return self._written

    def open(self) -> "SegmentedWriter":
        self._fh = open(self.tmp_path, "wb")
        return self

    @staticmethod
    def split_segments(data: bytes, segment_size: int) -> list[bytes]:
        return [data[i:i + segment_size] for i in range(0, len(data), segment_size)]

    def write_segment(self, segment: bytes, *, is_last: bool) -> None:
        if self._fh is None:
            raise SegmentedWriteError("分段写入器尚未 open")
        if is_last and self.fail_on_last:
            # 先把前面的段都落盘，再在最后一段真实失败：模拟"绝大部分已持久化"的崩溃
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None
            raise SegmentedWriteError(
                f"最后一段写入失败（注入）：{self.tmp_path} 已持久化 {self._written} 字节，"
                f"剩余 {len(segment)} 字节未写"
            )
        self._fh.write(segment)
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._written += len(segment)

    def close(self) -> None:
        if self._fh is not None and not self._fh.closed:
            self._fh.close()
        self._fh = None

    def write_all(self, data: bytes) -> int:
        segments = self.split_segments(data, self.segment_size)
        self.open()
        try:
            for index, segment in enumerate(segments):
                self.write_segment(segment, is_last=index == len(segments) - 1)
        finally:
            self.close()
        return self._written

    def cleanup(self) -> None:
        self.close()
        if os.path.exists(self.tmp_path):
            os.remove(self.tmp_path)


def journal_id_for(codename: str, relpath: str) -> str:
    return digest_json({"codename": codename, "relpath": relpath})[:16]
