"""独立检查器取证：日志篡改、越权可见、审批重验、视图/CAS 校验。

关键：inspector 包不导入 quarprom，测试同时断言这一独立性约束。
"""

import json
import os

from quarprom.promoter import PromotionRequest, Promoter
from quarprom.paths import atomic_write

from inspector import checker as checker

from tests.helpers import WorkspaceCase


class IndependenceTests(WorkspaceCase):
    def test_checker_module_does_not_import_quarprom(self):
        import inspect
        src = inspect.getsource(checker)
        self.assertNotIn("import quarprom", src)
        self.assertNotIn("from quarprom", src)


class CheckerTests(WorkspaceCase):
    def _promote(self, codename: str, relpath: str, **kw):
        src, data, dig = self.make_artifact(codename)
        ap = self.make_approval(codename, dig, src)
        promoter = Promoter(self.ws, self.keystore)
        return promoter.promote(PromotionRequest(
            codename=codename, source=src, relpath=relpath,
            approval=ap, content=data, **kw
        ))

    def test_clean_workspace_passes(self):
        self._promote("alpha", "proj/alpha.bin")
        report = checker.run_check(self.ws.root)
        self.assertTrue(report["ok"], msg=json.dumps(report["findings"], ensure_ascii=False))
        self.assertEqual(report["findings"], [])
        self.assertIsNone(report["earliest_unauthorized_evidence"])

    def test_aborted_but_visible_produces_earliest_evidence(self):
        result = self._promote("beta", "proj/beta.bin",
                               fail_last_segment=True, segment_size=128)
        self.assertEqual(result.status, "ABORTED")
        _q, a_root = self.ws.bound_roots()
        target = os.path.join(a_root, "proj", "beta.bin")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        atomic_write(target, b"re-created after abort")
        report = checker.run_check(self.ws.root)
        self.assertFalse(report["ok"])
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("C6_ABORTED_BUT_VISIBLE", codes)
        earliest = report["earliest_unauthorized_evidence"]
        self.assertEqual(earliest["code"], "C6_ABORTED_BUT_VISIBLE")
        self.assertEqual(earliest["relpath"], "proj/beta.bin")
        self.assertIsNotNone(earliest["first_visible_ts_ns"])
        self.assertEqual(earliest["evidence"]["abort_seq"], result.decision.seq)

    def test_undecided_ghost_file_detected(self):
        _q, a_root = self.ws.bound_roots()
        ghost = os.path.join(a_root, "shadow", "ghost.bin")
        os.makedirs(os.path.dirname(ghost), exist_ok=True)
        atomic_write(ghost, b"ghost")
        report = checker.run_check(self.ws.root)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("C6_UNDECIDED_VISIBLE", codes)
        self.assertEqual(report["earliest_unauthorized_evidence"]["code"],
                         "C6_UNDECIDED_VISIBLE")

    def test_hash_chain_tampering_is_fatal(self):
        self._promote("alpha", "proj/alpha.bin")
        # 直接改写决定日志中某条 payload（哈希链必然断裂）
        with open(self.ws.log_path, "rb") as fh:
            lines = fh.read().splitlines()
        rec = json.loads(lines[-1].decode("utf-8"))
        rec["payload"]["digest"] = "f" * 64
        lines[-1] = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with open(self.ws.log_path, "wb") as fh:
            fh.write(b"\n".join(lines) + b"\n")
        report = checker.run_check(self.ws.root)
        self.assertTrue(report["fatal"])
        codes = [f["code"] for f in report["findings"]]
        self.assertTrue(
            {"C2_HASH_MISMATCH", "C2_CHAIN_BROKEN"} & set(codes),
            msg=f"未捕获哈希链篡改：{codes}",
        )

    def test_bad_approval_signature_detected(self):
        self._promote("alpha", "proj/alpha.bin")
        ap_path = os.path.join(self.ws.root, "approvals", "alpha.approval.json")
        with open(ap_path, "rb") as fh:
            ap = json.loads(fh.read().decode("utf-8"))
        ap["signatures"]["alice"]["sig"] = "0" * 64
        with open(ap_path, "wb") as fh:
            fh.write(json.dumps(ap, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        report = checker.run_check(self.ws.root)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("C3_BAD_SIGNATURE", codes)

    def test_missing_second_controller_detected(self):
        self._promote("alpha", "proj/alpha.bin")
        ap_path = os.path.join(self.ws.root, "approvals", "alpha.approval.json")
        with open(ap_path, "rb") as fh:
            ap = json.loads(fh.read().decode("utf-8"))
        del ap["signatures"]["bob"]
        with open(ap_path, "wb") as fh:
            fh.write(json.dumps(ap, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        report = checker.run_check(self.ws.root)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("C3_NOT_DUAL_CONTROL", codes)

    def test_view_manifest_and_blob_corruption_detected(self):
        result = self._promote("alpha", "proj/alpha.bin")
        # 破坏 CAS 内容块
        manifest = result.view.manifest
        dig = manifest["files"]["proj/alpha.bin"]["digest"]
        blob = os.path.join(self.ws.blobs_dir, dig[:2], dig[2:4], dig)
        self.assertTrue(os.path.exists(blob))
        with open(blob, "r+b") as fh:
            fh.seek(0)
            fh.write(b"CORRUPTED")
        report = checker.run_check(self.ws.root)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("C8_BLOB_CORRUPT", codes)

    def test_reparse_point_scan_detects_inside_root_alias(self):
        self._promote("alpha", "proj/alpha.bin")
        _q, a_root = self.ws.bound_roots()
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside, exist_ok=True)
        link = os.path.join(a_root, "evilmount")
        self.make_junction(link, outside)
        report = checker.run_check(self.ws.root)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("C5_REPARSE_POINT", codes)
