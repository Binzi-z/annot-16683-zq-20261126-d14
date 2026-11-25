"""6 万条基准的正确性测试（用较小规模保证测试速度，默认参数另由 demo 跑满 6 万）。"""

import os

from quarprom import benchmark as bench
from quarprom.views import compute_dir_digests, compute_dir_digests_filtered

from tests.helpers import WorkspaceCase


class BenchmarkConsistencyTests(WorkspaceCase):
    N = 6000
    DIRS = 60
    AFFECTED = ["d0000", "d0007", "d0030"]

    def test_manifest_incremental_matches_full(self):
        result = bench.benchmark_manifest(
            n=self.N, dirs=self.DIRS, affected_dirs=self.AFFECTED
        )
        self.assertTrue(result.consistent)
        self.assertEqual(result.total_files, self.N)
        self.assertLess(result.affected_seconds, result.full_seconds)
        self.assertGreater(result.speedup, 1.0)
        # 受影响条目数远小于全量
        self.assertLess(result.affected_digest_count, result.full_digest_count)

    def test_physical_incremental_matches_full_after_mutation(self):
        tree = os.path.join(self.tmp, "bench-tree")
        os.makedirs(tree, exist_ok=True)
        bench.generate_synthetic_tree(tree, n=self.N, dirs=self.DIRS)
        baseline = compute_dir_digests(tree)
        changed = bench.mutate_physical(tree, self.AFFECTED, n=self.N, dirs=self.DIRS)
        self.assertTrue(changed)
        result = bench.benchmark_physical(
            tree, self.AFFECTED, n=self.N, dirs=self.DIRS
        )
        self.assertTrue(result.consistent)
        full = compute_dir_digests(tree)
        inc = compute_dir_digests_filtered(tree, set(self.AFFECTED))
        # 受影响目录：两种口径结果一致，且相对基线确实发生变化
        for top in self.AFFECTED:
            self.assertEqual(full[top], inc[top])
            self.assertNotEqual(full[top], baseline[top])
        # 未受影响目录：摘要与基线完全相同
        for top, value in baseline.items():
            if top not in self.AFFECTED:
                self.assertEqual(full[top], value)

    def test_synthetic_data_is_deterministic(self):
        a = bench.synthetic_manifest_entries(n=1000, dirs=20, seed=42)
        b = bench.synthetic_manifest_entries(n=1000, dirs=20, seed=42)
        self.assertEqual(a, b)
        c = bench.synthetic_manifest_entries(n=1000, dirs=20, seed=43)
        self.assertNotEqual(a, c)
