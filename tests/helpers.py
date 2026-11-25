"""测试公共夹具。"""

import os
import shutil
import subprocess
import tempfile
import unittest

from quarprom import approval as approval_mod
from quarprom.digest import sha256_file
from quarprom.paths import atomic_write
from quarprom.workspace import Workspace


class WorkspaceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="quarprom-test-")
        self.ws_root = os.path.join(self.tmp, "ws")
        self.qdir = os.path.join(self.tmp, "quarantine")
        self.adir = os.path.join(self.tmp, "allowed")
        self.ws = Workspace.create(self.ws_root, self.qdir, self.adir)
        self.keystore = approval_mod.KeyStore.create(
            self.ws.keystore_path, ("alice", "bob")
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_artifact(self, codename: str, payload: bytes | None = None) -> tuple[str, bytes, str]:
        path = os.path.join(self.qdir, f"{codename}.bin")
        data = payload if payload is not None else (
            f"fictional {codename}\n".encode("utf-8") + bytes(range(256)) * 8
        )
        atomic_write(path, data)
        return path, data, sha256_file(path)

    def make_approval(self, codename: str, digest_hex: str, source: str):
        q_root, a_root = self.ws.bound_roots()
        aliases = [source, os.path.abspath(source).lower()]
        return approval_mod.issue_approval(
            keystore=self.keystore, target_root=a_root,
            full_digest=digest_hex, codename=codename,
            source_aliases=aliases, signers=("alice", "bob"),
        )

    def make_junction(self, link: str, target: str) -> None:
        os.makedirs(os.path.dirname(link), exist_ok=True)
        if os.path.exists(link):
            subprocess.run(["cmd", "/c", "rmdir", link], capture_output=True)
        proc = subprocess.run(["cmd", "/c", "mklink", "/J", link, target],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            self.skipTest(f"mklink /J 不可用：{proc.stderr}")
