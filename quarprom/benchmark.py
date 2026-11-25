"""六万条本地合成清单基准：只重核受影响目录 vs 全量计算。

两种口径都测，保证结论可信：
  A. 物理目录口径：真实生成 60000 个小文件，全量 walk+SHA-256 vs 只 walk 受影响目录；
  B. 清单口径：60000 条 (relpath,digest,size) 合成清单，全量聚合 vs 只聚合受影响条目。
增量结果必须与全量结果在受影响目录上逐字节一致（聚合摘要相等），否则基准本身判失败。
"""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass
from typing import Any

from .digest import canonical_json, digest_json, sha256_bytes
from .paths import ensure_dir, relative_posix, resolved
from .views import build_manifest, compute_dir_digests, compute_dir_digests_filtered

DEFAULT_N = 60_000
DEFAULT_DIRS = 300
_SEED = 20261126


# ---------------------------------------------------------------- 合成数据

def generate_synthetic_tree(root: str, n: int = DEFAULT_N, dirs: int = DEFAULT_DIRS,
                            seed: int = _SEED) -> list[str]:
    """在 root 下生成 n 个确定性小文件，均匀分布到 dirs 个目录。返回全部文件路径。"""
    root = resolved(root)
    rng = random.Random(seed)
    created: list[str] = []
    for i in range(n):
        top = f"d{i % dirs:04d}"
        sub = f"s{(i // dirs) % 50:03d}"
        d = os.path.join(root, top, sub)
        ensure_dir(d)
        name = f"artifact_{i:06d}.bin"
        path = os.path.join(d, name)
        # 确定性内容：序号 + 随机盐，文件足够小但跨多段（约 200~900 字节）
        salt = rng.randrange(1 << 32)
        payload = (f"codename=syn-{i:06d}\nsalt={salt:08x}\n".encode("utf-8")
                   + bytes((j * 7 + i) & 0xFF for j in range(128)))
        if not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(payload)
        created.append(path)
    return created


def synthetic_manifest_entries(n: int = DEFAULT_N, dirs: int = DEFAULT_DIRS,
                               seed: int = _SEED) -> list[tuple[str, str, int]]:
    """生成 n 条纯清单条目（不落盘），用于清单口径的基准。"""
    rng = random.Random(seed)
    entries: list[tuple[str, str, int]] = []
    for i in range(n):
        top = f"d{i % dirs:04d}"
        rel = f"{top}/s{(i // dirs) % 50:03d}/artifact_{i:06d}.bin"
        payload = (f"codename=syn-{i:06d}\n".encode("utf-8")
                   + rng.randbytes(128))
        entries.append((rel, sha256_bytes(payload), len(payload)))
    return entries


# ---------------------------------------------------------------- 清单口径聚合

def _aggregate(entries: list[tuple[str, str, int]]) -> dict[str, str]:
    buckets: dict[str, list[tuple[str, str, int]]] = {}
    for rel, dig, size in entries:
        top = rel.split("/", 1)[0]
        buckets.setdefault(top, []).append((rel, dig, size))
    return {top: digest_json(build_manifest(sorted(items))) for top, items in buckets.items()}


def _aggregate_filtered(entries: list[tuple[str, str, int]], only: set[str]) -> dict[str, str]:
    return _aggregate([e for e in entries if e[0].split("/", 1)[0] in only])


# ---------------------------------------------------------------- 基准主体

@dataclass
class BenchResult:
    mode: str
    total_files: int
    total_dirs: int
    affected_dirs: int
    full_seconds: float
    affected_seconds: float
    speedup: float
    full_digest_count: int
    affected_digest_count: int
    consistent: bool
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode, "total_files": self.total_files,
            "total_dirs": self.total_dirs, "affected_dirs": self.affected_dirs,
            "full_seconds": round(self.full_seconds, 6),
            "affected_seconds": round(self.affected_seconds, 6),
            "speedup": round(self.speedup, 2),
            "full_digest_count": self.full_digest_count,
            "affected_digest_count": self.affected_digest_count,
            "consistent": self.consistent, "detail": self.detail,
        }


def _timed(fn) -> tuple[Any, float]:
    t0 = time.perf_counter()
    out = fn()
    return out, time.perf_counter() - t0


def benchmark_physical(root: str, affected_dirs: list[str], *,
                       n: int = DEFAULT_N, dirs: int = DEFAULT_DIRS) -> BenchResult:
    """物理口径：真实文件树全量重算 vs 受影响目录重核。"""
    paths = generate_synthetic_tree(root, n=n, dirs=dirs)
    affected_set = set(affected_dirs)

    baseline, t_base = _timed(lambda: compute_dir_digests(root))
    full_after, t_full = _timed(lambda: compute_dir_digests(root))
    inc_after, t_inc = _timed(lambda: compute_dir_digests_filtered(root, affected_set))

    consistent = all(full_after[top] == inc_after.get(top) for top in affected_set)
    unchanged = all(baseline[top] == full_after[top] for top in baseline if top not in affected_set)
    return BenchResult(
        mode="physical-tree", total_files=len(paths), total_dirs=len(baseline),
        affected_dirs=len(affected_set), full_seconds=t_full, affected_seconds=t_inc,
        speedup=(t_full / t_inc) if t_inc > 0 else float("inf"),
        full_digest_count=len(paths),
        affected_digest_count=sum(
            1 for p in paths if relative_posix(root, p).split("/", 1)[0] in affected_set
        ),
        consistent=consistent and unchanged,
        detail={"baseline_seconds": round(t_base, 6),
                "note": "consistent=True 表示增量重核与全量在受影响目录上聚合摘要逐字节一致，"
                        "且未受影响目录摘要保持不变"},
    )


def benchmark_manifest(*, n: int = DEFAULT_N, dirs: int = DEFAULT_DIRS,
                       affected_dirs: list[str] | None = None) -> BenchResult:
    """清单口径：6 万条合成清单的全量聚合 vs 只聚合受影响条目。"""
    entries = synthetic_manifest_entries(n=n, dirs=dirs)
    if affected_dirs is None:
        # 默认取 3 个受影响目录（约 600 条），模拟一次小范围晋升
        affected_dirs = ["d0000", "d0001", "d0150"]
    affected_set = set(affected_dirs)

    full_after, t_full = _timed(lambda: _aggregate(entries))
    inc_after, t_inc = _timed(lambda: _aggregate_filtered(entries, affected_set))

    consistent = all(full_after[top] == inc_after.get(top) for top in affected_set)
    affected_entries = sum(1 for rel, _d, _s in entries if rel.split("/", 1)[0] in affected_set)
    return BenchResult(
        mode="synthetic-manifest", total_files=n, total_dirs=len(full_after),
        affected_dirs=len(affected_set), full_seconds=t_full, affected_seconds=t_inc,
        speedup=(t_full / t_inc) if t_inc > 0 else float("inf"),
        full_digest_count=n, affected_digest_count=affected_entries,
        consistent=consistent,
        detail={"affected_dirs": sorted(affected_set),
                "sample_full_digest": next(iter(full_after.items())),
                "note": "清单口径下每条摘要已预算，聚合成本仅为归并与一次 JSON 哈希"},
    )


def mutate_physical(root: str, affected_dirs: list[str], *, n: int = DEFAULT_N,
                    dirs: int = DEFAULT_DIRS, files_per_dir: int = 2) -> list[str]:
    """在受影响目录里真实改写若干文件，制造"受影响目录"。返回被改文件的 relpath。"""
    changed: list[str] = []
    for top in affected_dirs:
        d = os.path.join(resolved(root), top)
        if not os.path.isdir(d):
            continue
        files: list[str] = []
        for dirpath, _dn, filenames in os.walk(d):
            files.extend(os.path.join(dirpath, f) for f in filenames)
        files.sort()
        for path in files[:files_per_dir]:
            with open(path, "ab") as fh:
                fh.write(b"\n# mutated-by-benchmark\n")
            changed.append(relative_posix(root, path))
    return changed
