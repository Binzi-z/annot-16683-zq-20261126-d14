"""内容寻址存储 + 不可变版本视图。

- blobs/ 按 sha256 分两层存放不可变内容块；同名内容天然去重，内容变了摘要必变。
- views/v<N>/manifest.json 是某一版"公开集合"的完整清单（逐文件 relpath -> digest,size），
  发布过程原子替换；旧版本目录永不原地修改，持续读者可以一直重放旧视图。
- 视图重放：逐条核对 manifest 中的摘要与 blob 实际摘要，任何偏差都判定视图损坏。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Iterable

from .digest import canonical_json, digest_json, sha256_file
from .errors import ViewReplayError
from .paths import atomic_write, ensure_dir, fsync_dir, hardlink_or_copy, relative_posix, resolved

MANIFEST_NAME = "manifest.json"
CURRENT_POINTER = "current.json"


def blob_path(blobs_dir: str, digest_hex: str) -> str:
    return os.path.join(blobs_dir, digest_hex[:2], digest_hex[2:4], digest_hex)


def put_blob(blobs_dir: str, src_path: str, digest_hex: str) -> str:
    """把制品放入内容寻址存储（硬链接优先），已存在则校验后复用。"""
    dst = blob_path(blobs_dir, digest_hex)
    if os.path.exists(dst):
        actual = sha256_file(dst)
        if actual != digest_hex:
            raise ViewReplayError(f"内容块 {digest_hex} 已存在但摘要不符，存储被污染")
        return dst
    ensure_dir(os.path.dirname(dst))
    hardlink_or_copy(src_path, dst)
    fsync_dir(os.path.dirname(dst))
    return dst


def build_manifest(entries: Iterable[tuple[str, str, int]]) -> dict[str, Any]:
    """entries: (relpath, digest, size)。"""
    files = {rel: {"digest": dig.lower(), "size": size} for rel, dig, size in entries}
    manifest = {"version": 1, "files": dict(sorted(files.items()))}
    manifest["manifest_digest"] = digest_json({"version": 1, "files": manifest["files"]})
    return manifest


def manifest_digest_of(manifest: dict[str, Any]) -> str:
    return digest_json({"version": manifest["version"], "files": manifest["files"]})


@dataclass(frozen=True)
class PublishedView:
    version: int
    dir: str
    manifest: dict[str, Any]


class ViewStore:
    def __init__(self, views_dir: str, blobs_dir: str):
        self.views_dir = resolved(views_dir)
        self.blobs_dir = resolved(blobs_dir)
        ensure_dir(self.views_dir)
        ensure_dir(self.blobs_dir)

    def view_dir(self, version: int) -> str:
        return os.path.join(self.views_dir, f"v{version}")

    def _pointer_path(self) -> str:
        return os.path.join(self.views_dir, CURRENT_POINTER)

    def current_version(self) -> int | None:
        p = self._pointer_path()
        if not os.path.exists(p):
            return None
        with open(p, "rb") as fh:
            return int(json.loads(fh.read().decode("utf-8"))["version"])

    def publish(self, manifest: dict[str, Any]) -> PublishedView:
        """发布下一版：写入新的不可变视图目录，再原子切换 current 指针。"""
        next_version = (self.current_version() or 0) + 1
        vdir = self.view_dir(next_version)
        if os.path.exists(vdir):
            raise ViewReplayError(f"视图版本目录已存在，发布不是单调追加：{vdir}")
        ensure_dir(vdir)
        atomic_write(os.path.join(vdir, MANIFEST_NAME), canonical_json(manifest))
        pointer = {
            "version": next_version,
            "manifest_digest": manifest["manifest_digest"],
            "view_dir": vdir,
        }
        atomic_write(self._pointer_path(), canonical_json(pointer))
        return PublishedView(next_version, vdir, manifest)

    def load_manifest(self, version: int) -> dict[str, Any]:
        path = os.path.join(self.view_dir(version), MANIFEST_NAME)
        with open(path, "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))

    def replay(self, version: int) -> dict[str, Any]:
        """重放指定旧版本视图：manifest 自洽 + 每个内容块摘要可复算。"""
        manifest = self.load_manifest(version)
        if manifest_digest_of(manifest) != manifest["manifest_digest"]:
            raise ViewReplayError(f"v{version} 清单自摘要不符，视图被篡改")
        for rel, entry in manifest["files"].items():
            bp = blob_path(self.blobs_dir, entry["digest"])
            if not os.path.exists(bp):
                raise ViewReplayError(f"v{version} 重放失败：{rel} 的内容块缺失 {entry['digest']}")
            actual = sha256_file(bp)
            if actual != entry["digest"]:
                raise ViewReplayError(
                    f"v{version} 重放失败：{rel} 内容块摘要 {actual} != 清单 {entry['digest']}"
                )
            if os.path.getsize(bp) != entry["size"]:
                raise ViewReplayError(f"v{version} 重放失败：{rel} 尺寸不符")
        return manifest

    def all_versions(self) -> list[int]:
        out = []
        for name in os.listdir(self.views_dir):
            if name.startswith("v") and name[1:].isdigit():
                out.append(int(name[1:]))
        return sorted(out)


# ---------------------------------------------------------------- 目录摘要树（基准测试复用）

def compute_dir_digests(root: str) -> dict[str, str]:
    """全量扫描：每个直接子目录 -> 该目录全部文件的聚合摘要（含根级文件聚合键 ''）。"""
    root = resolved(root)
    buckets: dict[str, list[tuple[str, str, int]]] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = relative_posix(root, full)
            top = rel.split("/", 1)[0] if "/" in rel else ""
            buckets.setdefault(top, []).append((rel, sha256_file(full), os.path.getsize(full)))
    return {top: digest_json(build_manifest(sorted(entries))) for top, entries in buckets.items()}


def recompute_affected(root: str, affected_dirs: Iterable[str]) -> dict[str, str]:
    """增量重核：只重算受影响目录的聚合摘要。"""
    return compute_dir_digests_filtered(root, set(affected_dirs))


def compute_dir_digests_filtered(root: str, only_tops: set[str]) -> dict[str, str]:
    root = resolved(root)
    buckets: dict[str, list[tuple[str, str, int]]] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = relative_posix(root, full)
            top = rel.split("/", 1)[0] if "/" in rel else ""
            if top not in only_tops:
                continue
            buckets.setdefault(top, []).append((rel, sha256_file(full), os.path.getsize(full)))
    return {top: digest_json(build_manifest(sorted(entries))) for top, entries in buckets.items()}
