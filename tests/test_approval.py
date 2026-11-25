"""双控制人审批：签名、四要素绑定、别名一致性。"""

import copy
import os

from quarprom import approval as am
from quarprom.digest import canonical_json, hmac_sign
from quarprom.errors import ApprovalError

from tests.helpers import WorkspaceCase


class ApprovalTests(WorkspaceCase):
    def _artifact(self, codename="alpha"):
        return self.make_artifact(codename)

    def test_valid_dual_control_approval(self):
        _src, _data, dig = self._artifact()
        q_root, a_root = self.ws.bound_roots()
        ap = am.issue_approval(
            keystore=self.keystore, target_root=a_root, full_digest=dig,
            codename="alpha", source_aliases=[_src], signers=("alice", "bob"),
        )
        binding = am.verify_approval(ap, keystore=self.keystore)
        self.assertEqual(binding["target_root"], am.resolved(a_root))
        self.assertEqual(binding["full_digest"], dig)
        self.assertEqual(len(ap["signatures"]), 2)

    def test_single_controller_rejected(self):
        _src, _data, dig = self._artifact()
        _q, a_root = self.ws.bound_roots()
        with self.assertRaises(ApprovalError):
            am.issue_approval(
                keystore=self.keystore, target_root=a_root, full_digest=dig,
                codename="alpha", source_aliases=[_src], signers=("alice", "alice"),
            )

    def test_tampered_signature_rejected(self):
        src, _data, dig = self._artifact()
        _q, a_root = self.ws.bound_roots()
        ap = am.issue_approval(
            keystore=self.keystore, target_root=a_root, full_digest=dig,
            codename="alpha", source_aliases=[src], signers=("alice", "bob"),
        )
        ap["signatures"]["alice"]["sig"] = "0" * 64
        with self.assertRaises(ApprovalError):
            am.verify_approval(ap, keystore=self.keystore)

    def test_target_root_binding_cannot_be_rewritten(self):
        src, _data, dig = self._artifact()
        _q, a_root = self.ws.bound_roots()
        ap = am.issue_approval(
            keystore=self.keystore, target_root=a_root, full_digest=dig,
            codename="alpha", source_aliases=[src], signers=("alice", "bob"),
        )
        # 偷改目标根后重签：若只换一个控制人，双签失效；换根后与实际根比对失败
        ap2 = copy.deepcopy(ap)
        ap2["target_root"] = am.resolved(os.path.join(self.tmp, "other-root"))
        with self.assertRaises(ApprovalError):
            am.verify_approval(ap2, keystore=self.keystore)

    def test_digest_binding_mismatch_rejected(self):
        src, _data, dig = self._artifact()
        _q, a_root = self.ws.bound_roots()
        ap = am.issue_approval(
            keystore=self.keystore, target_root=a_root, full_digest=dig,
            codename="alpha", source_aliases=[src], signers=("alice", "bob"),
        )
        binding = am.verify_approval(ap, keystore=self.keystore)
        with self.assertRaises(ApprovalError):
            am.check_approval_matches(
                binding, target_root=a_root, full_digest="f" * 64,
                codename="alpha", actual_source=src,
            )

    def test_codename_binding_enforced(self):
        src, _data, dig = self._artifact()
        _q, a_root = self.ws.bound_roots()
        ap = am.issue_approval(
            keystore=self.keystore, target_root=a_root, full_digest=dig,
            codename="alpha", source_aliases=[src], signers=("alice", "bob"),
        )
        binding = am.verify_approval(ap, keystore=self.keystore)
        with self.assertRaises(ApprovalError):
            am.check_approval_matches(
                binding, target_root=a_root, full_digest=dig,
                codename="omega", actual_source=src,
            )

    def test_undeclared_alias_source_rejected(self):
        src, _data, dig = self._artifact()
        _q, a_root = self.ws.bound_roots()
        other = os.path.join(self.qdir, "other.bin")
        with open(other, "wb") as fh:
            fh.write(b"different content entirely")
        ap = am.issue_approval(
            keystore=self.keystore, target_root=a_root, full_digest=dig,
            codename="alpha", source_aliases=[src], signers=("alice", "bob"),
        )
        binding = am.verify_approval(ap, keystore=self.keystore)
        with self.assertRaises(ApprovalError):
            am.check_approval_matches(
                binding, target_root=a_root, full_digest=dig,
                codename="alpha", actual_source=other,
            )

    def test_alias_pointing_to_different_object_rejected(self):
        src, _data, dig = self._artifact()
        decoy = os.path.join(self.qdir, "decoy.bin")
        with open(decoy, "wb") as fh:
            fh.write(b"decoy")
        _q, a_root = self.ws.bound_roots()
        # 审批把两个不同物理对象都声明为"别名"——检查必须发现它们不是同一对象
        ap = am.issue_approval(
            keystore=self.keystore, target_root=a_root, full_digest=dig,
            codename="alpha", source_aliases=[src, decoy],
            signers=("alice", "bob"),
        )
        binding = am.verify_approval(ap, keystore=self.keystore)
        with self.assertRaises(ApprovalError):
            am.check_approval_matches(
                binding, target_root=a_root, full_digest=dig,
                codename="alpha", actual_source=src,
            )

    def test_replayed_signature_over_new_binding_invalid(self):
        src, _data, dig = self._artifact()
        _q, a_root = self.ws.bound_roots()
        ap = am.issue_approval(
            keystore=self.keystore, target_root=a_root, full_digest=dig,
            codename="alpha", source_aliases=[src], signers=("alice", "bob"),
        )
        # 构造另一份绑定并尝试复用旧签名（签名消息覆盖整个绑定载荷）
        forged = copy.deepcopy(ap)
        forged["codename"] = "alpha-forged"
        with self.assertRaises(ApprovalError):
            am.verify_approval(forged, keystore=self.keystore)
        # 直接用密钥对旧消息的签名放到新消息上也必然失败
        ctrl = self.keystore.get("alice")
        self.assertNotEqual(
            hmac_sign(ctrl.key, canonical_json({"x": 1})),
            hmac_sign(ctrl.key, canonical_json({"x": 2})),
        )
