"""仅追加的哈希链决定日志（append-only hash-chained JSONL）。

每条记录：
  seq      单调递增序号（从 0 开始）
  ts_ns    写入时刻（time.time_ns，检查器用它判定"最早"可见时间）
  kind     记录类型：PROMOTED / ABORTED / RECOVERED / VIEW_PUBLISHED
  payload  类型相关内容
  prev     前一条记录的 record_hash（创世记录为 64 个 0）
  record_hash = sha256(canonical_json(除 record_hash 外的全部字段))
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Iterator

from .digest import canonical_json, digest_json
from .errors import LogIntegrityError
from .paths import atomic_write, ensure_dir, fsync_dir

GENESIS_PREV = "0" * 64
VALID_KINDS = frozenset({"PROMOTED", "ABORTED", "RECOVERED", "VIEW_PUBLISHED"})


@dataclass(frozen=True)
class LogRecord:
    seq: int
    ts_ns: int
    kind: str
    payload: dict[str, Any]
    prev: str
    record_hash: str

    def to_line(self) -> bytes:
        return canonical_json({
            "seq": self.seq,
            "ts_ns": self.ts_ns,
            "kind": self.kind,
            "payload": self.payload,
            "prev": self.prev,
            "record_hash": self.record_hash,
        }) + b"\n"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "LogRecord":
        return cls(
            seq=int(raw["seq"]), ts_ns=int(raw["ts_ns"]), kind=raw["kind"],
            payload=raw["payload"], prev=raw["prev"], record_hash=raw["record_hash"],
        )


class DecisionLog:
    def __init__(self, path: str):
        self.path = path
        ensure_dir(os.path.dirname(path))

    def append(self, kind: str, payload: dict[str, Any]) -> LogRecord:
        if kind not in VALID_KINDS:
            raise LogIntegrityError(f"非法决定记录类型：{kind}")
        records = list(self.read_all()) if os.path.exists(self.path) else []
        seq = len(records)
        prev = records[-1].record_hash if records else GENESIS_PREV
        base = {
            "seq": seq,
            "ts_ns": time.time_ns(),
            "kind": kind,
            "payload": payload,
            "prev": prev,
        }
        record = LogRecord(
            seq=seq, ts_ns=base["ts_ns"], kind=kind, payload=payload,
            prev=prev, record_hash=digest_json(base),
        )
        # 追加写 + 落盘；不重写历史，保证 append-only 语义
        with open(self.path, "ab") as fh:
            fh.write(record.to_line())
            fh.flush()
            os.fsync(fh.fileno())
        fsync_dir(os.path.dirname(self.path))
        return record

    def read_all(self) -> Iterator[LogRecord]:
        if not os.path.exists(self.path):
            return  # 尚无任何决定：空迭代器
        with open(self.path, "rb") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line.decode("utf-8"))
                    yield LogRecord.from_dict(raw)
                except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError) as exc:
                    raise LogIntegrityError(
                        f"决定日志第 {lineno} 行无法解析，日志被截断或损坏：{exc}"
                    ) from None

    def verify_chain(self) -> list[LogRecord]:
        """重算整条哈希链，返回全部记录；任何断裂/改写都抛错。"""
        records: list[LogRecord] = []
        prev = GENESIS_PREV
        for expected_seq, rec in enumerate(self.read_all()):
            if rec.seq != expected_seq:
                raise LogIntegrityError(
                    f"序号断裂：期望 {expected_seq}，实际 {rec.seq}"
                )
            if rec.prev != prev:
                raise LogIntegrityError(
                    f"记录 {rec.seq} 的 prev 与前一条哈希不符（日志被改写或分叉）"
                )
            base = {
                "seq": rec.seq, "ts_ns": rec.ts_ns, "kind": rec.kind,
                "payload": rec.payload, "prev": rec.prev,
            }
            if digest_json(base) != rec.record_hash:
                raise LogIntegrityError(f"记录 {rec.seq} 的 record_hash 不匹配（内容被篡改）")
            records.append(rec)
            prev = rec.record_hash
        return records

    def latest_decisions(self) -> dict[str, LogRecord]:
        """按相对路径（relpath）折叠出每个对象的最新有效决定。

        只有 PROMOTED/ABORTED 是决定；VIEW_PUBLISHED/RECOVERED 等事件不参与折叠。
        """
        latest: dict[str, LogRecord] = {}
        for rec in self.verify_chain():
            if rec.kind not in ("PROMOTED", "ABORTED"):
                continue
            rel = rec.payload.get("relpath")
            if rel is None:
                continue
            latest[rel] = rec
        return latest


def write_marker(path: str, obj: Any) -> None:
    atomic_write(path, canonical_json(obj))
