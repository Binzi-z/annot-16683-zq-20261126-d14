"""持续读者：持有旧视图期间并发发布下一版，旧视图必须可重放。"""

import os

from quarprom.digest import sha256_bytes
from quarprom.reader import PersistentReader, concurrent_publish_with_stale_reader
from quarprom.views import ViewStore, blob_path, build_manifest, put_blob

from tests.helpers import WorkspaceCase


class ReaderViewTests(WorkspaceCase):
    def _publish(self, store, name, payload: bytes):
        # 与真实晋升一致：内容先入内容寻址存储，再发布引用它的不可变 manifest
        src = os.path.join(self.qdir, name.replace("/", "_"))
        os.makedirs(os.path.dirname(src), exist_ok=True)
        with open(src, "wb") as fh:
            fh.write(payload)
        dig = sha256_bytes(payload)
        put_blob(self.ws.blobs_dir, src, dig)
        cur = store.current_version()
        files = dict(store.load_manifest(cur)["files"]) if cur else {}
        files[name] = {"digest": dig, "size": len(payload)}
        return store.publish(build_manifest(
            (rel, e["digest"], e["size"]) for rel, e in files.items()
        ))

    def test_stale_reader_replays_while_next_version_publishes(self):
        store = ViewStore(self.ws.views_dir, self.ws.blobs_dir)
        v1 = self._publish(store, "a/first.bin", b"first-content")
        # 第二版引用的新内容同样先入 CAS
        second_src = os.path.join(self.qdir, "second.bin")
        with open(second_src, "wb") as fh:
            fh.write(b"second")
        second_dig = sha256_bytes(b"second")
        put_blob(self.ws.blobs_dir, second_src, second_dig)
        observed = concurrent_publish_with_stale_reader(
            store,
            next_manifest=build_manifest([
                ("a/first.bin", v1.manifest["files"]["a/first.bin"]["digest"],
                 v1.manifest["files"]["a/first.bin"]["size"]),
                ("b/second.bin", second_dig, 6),
            ]),
        )
        self.assertTrue(observed["old_replay_ok"])
        self.assertEqual(observed["reader_held_version"], 1)
        self.assertEqual(observed["published_version"], 2)
        self.assertEqual(observed["current_after_publish"], 2)
        self.assertTrue(observed["old_version_still_exists"])
        self.assertEqual(observed["old_replay_files"], 1)
        self.assertEqual(observed["new_replay_files"], 2)

    def test_old_views_remain_indefinitely_replayable_after_many_publishes(self):
        store = ViewStore(self.ws.views_dir, self.ws.blobs_dir)
        for i in range(5):
            self._publish(store, f"d/file{i}.bin", f"content-{i}".encode())
        self.assertEqual(store.all_versions(), [1, 2, 3, 4, 5])
        reader = PersistentReader("old-hand", store, version=2)
        snap = reader.open_view()
        self.assertEqual(snap.file_count, 2)
        replayed = reader.replay_old_view()
        self.assertEqual(replayed.manifest_digest, snap.manifest_digest)
        # 最新版有 5 个文件，旧版仍只有 2 个，互不影响
        self.assertEqual(len(store.replay(5)["files"]), 5)
        self.assertEqual(len(store.replay(2)["files"]), 2)

    def test_cas_blob_dedup_and_immutability(self):
        path = os.path.join(self.qdir, "dedup.bin")
        with open(path, "wb") as fh:
            fh.write(b"same-bytes")
        dig = sha256_bytes(b"same-bytes")
        p1 = put_blob(self.ws.blobs_dir, path, dig)
        p2 = put_blob(self.ws.blobs_dir, path, dig)
        self.assertEqual(p1, p2)
        self.assertTrue(os.path.exists(blob_path(self.ws.blobs_dir, dig)))
