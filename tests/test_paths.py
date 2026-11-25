"""路径防御：别名偷换控制根的各类尝试都必须被拒绝。"""

import os
import subprocess

from quarprom.errors import RootAliasError
from quarprom.paths import assert_under_root, is_reparse_point, resolved

from tests.helpers import WorkspaceCase


class PathDefenseTests(WorkspaceCase):
    def test_dotdot_traversal_rejected(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside, exist_ok=True)
        secret = os.path.join(outside, "secret.bin")
        with open(secret, "wb") as fh:
            fh.write(b"x")
        evil = os.path.join(self.qdir, "..", "outside", "secret.bin")
        with self.assertRaises(RootAliasError):
            assert_under_root(self.qdir, evil, what="遍历来源")

    def test_case_and_separator_normalized(self):
        path = os.path.join(self.qdir, "Sub", "File.BIN")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(b"x")
        canon = assert_under_root(self.qdir, path)
        self.assertEqual(canon, resolved(path))
        # 大小写变体仍解析到同一规范路径
        variant = path.upper() if path.lower() != path else path.lower()
        self.assertEqual(assert_under_root(self.qdir, variant), canon)

    def test_junction_escape_rejected(self):
        outside = os.path.join(self.tmp, "stash")
        os.makedirs(outside, exist_ok=True)
        with open(os.path.join(outside, "stolen.bin"), "wb") as fh:
            fh.write(b"stolen")
        link = os.path.join(self.qdir, "evil")
        self.make_junction(link, outside)
        self.assertTrue(is_reparse_point(link))
        evil_source = os.path.join(link, "stolen.bin")
        with self.assertRaises(RootAliasError):
            assert_under_root(self.qdir, evil_source, what="junction 来源")

    def test_inside_root_junction_also_rejected(self):
        real_dir = os.path.join(self.qdir, "real")
        os.makedirs(real_dir, exist_ok=True)
        with open(os.path.join(real_dir, "a.bin"), "wb") as fh:
            fh.write(b"a")
        link = os.path.join(self.qdir, "alias")
        self.make_junction(link, real_dir)
        # 即使解析后仍在根内，根内重解析点别名本身也必须被拒绝
        with self.assertRaises(RootAliasError):
            assert_under_root(self.qdir, os.path.join(link, "a.bin"), what="根内别名")

    def test_legitimate_path_accepted(self):
        good = os.path.join(self.qdir, "nested", "deep", "ok.bin")
        os.makedirs(os.path.dirname(good), exist_ok=True)
        with open(good, "wb") as fh:
            fh.write(b"ok")
        self.assertEqual(assert_under_root(self.qdir, good), resolved(good))

    def test_target_root_cannot_be_swapped(self):
        # 允许区外的路径不能伪装成允许区目标
        outside = os.path.join(self.tmp, "elsewhere", "x.bin")
        os.makedirs(os.path.dirname(outside), exist_ok=True)
        with open(outside, "wb") as fh:
            fh.write(b"x")
        with self.assertRaises(RootAliasError):
            assert_under_root(self.adir, outside, what="越界目标")
        # junction 把外部目录挂进允许区同样拒绝
        link = os.path.join(self.adir, "mount")
        self.make_junction(link, os.path.join(self.tmp, "elsewhere"))
        with self.assertRaises(RootAliasError):
            assert_under_root(self.adir, os.path.join(link, "x.bin"), what="挂载点目标")
        subprocess.run(["cmd", "/c", "rmdir", link], capture_output=True)
