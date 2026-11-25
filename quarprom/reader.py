"""持续读者：持有旧版本视图期间，晋升并发发布下一版；旧视图必须仍可完整重放。

不可变版本 + 内容寻址存储保证：
  - 读者打开 vN 时拿到的是不可变目录 views/vN/ 与不可变 blob；
  - 发布 v(N+1) 只新增文件并原子切换 current 指针，绝不原地改旧视图；
  - 因此读者全程持有旧引用即可重放，无需加锁、无需读屏障。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from .views import ViewStore


@dataclass(frozen=True)
class ReaderSnapshot:
    reader: str
    version: int
    manifest: dict[str, Any]
    file_count: int
    manifest_digest: str


class PersistentReader:
    """模拟一个长生命周期读者：打开某一版后，即使 current 指针前进也继续看旧版。"""

    def __init__(self, name: str, store: ViewStore, version: int | None = None):
        self.name = name
        self.store = store
        self.version = version if version is not None else (store.current_version() or 0)
        self._snapshot: ReaderSnapshot | None = None

    def open_view(self) -> ReaderSnapshot:
        manifest = self.store.load_manifest(self.version)
        self._snapshot = ReaderSnapshot(
            reader=self.name, version=self.version, manifest=manifest,
            file_count=len(manifest["files"]),
            manifest_digest=manifest["manifest_digest"],
        )
        return self._snapshot

    def replay_old_view(self) -> ReaderSnapshot:
        """重放自己持有的旧版：逐 blob 重算摘要（ViewStore.replay 全量校验）。"""
        manifest = self.store.replay(self.version)
        return ReaderSnapshot(
            reader=self.name, version=self.version, manifest=manifest,
            file_count=len(manifest["files"]),
            manifest_digest=manifest["manifest_digest"],
        )


def concurrent_publish_with_stale_reader(
    store: ViewStore, *, next_manifest: dict[str, Any], reader_hold_seconds: float = 0.05,
) -> dict[str, Any]:
    """真实线程并发：读者持有旧版 -> 发布者发布下一版 -> 读者重放旧版。

    返回各阶段观察到的版本号与重放结果，用于断言"旧视图仍可重放、新视图已可见"。
    """
    observed: dict[str, Any] = {}
    old_version = store.current_version()
    barrier = threading.Barrier(2, timeout=30)

    def reader_job() -> None:
        reader = PersistentReader("stale-reader", store, old_version)
        snap = reader.open_view()
        observed["reader_held_version"] = snap.version
        observed["reader_held_files"] = snap.file_count
        barrier.wait()  # 与发布者同时起跑，最大化并发窗口
        # 发布期间持续重放旧版两次，证明任何时刻旧版都稳定可读
        first = reader.replay_old_view()
        second = reader.replay_old_view()
        observed["old_replay_ok"] = (
            first.manifest_digest == snap.manifest_digest
            and second.manifest_digest == snap.manifest_digest
        )
        observed["old_replay_files"] = first.file_count

    def publisher_job() -> None:
        barrier.wait()
        published = store.publish(next_manifest)
        observed["published_version"] = published.version
        observed["current_after_publish"] = store.current_version()

    t_reader = threading.Thread(target=reader_job, name="persistent-reader")
    t_publisher = threading.Thread(target=publisher_job, name="view-publisher")
    t_reader.start()
    t_publisher.start()
    t_reader.join()
    t_publisher.join()

    # 发布完成后，新旧两版都必须能独立重放
    observed["new_replay_files"] = len(store.replay(observed["published_version"])["files"])
    observed["old_version_still_exists"] = old_version in store.all_versions()
    observed["all_versions"] = store.all_versions()
    return observed
