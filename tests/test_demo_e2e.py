"""端到端演示作为测试运行：run_demo.main 内部全部用独立子进程驱动，
包括 os._exit 真实进程死亡后的重启恢复、原生 junction 攻击、6 万条基准。
单独执行：python -m unittest tests.test_demo_e2e
"""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import run_demo  # noqa: E402


class EndToEndDemoTests(unittest.TestCase):
    def test_full_demo_passes(self):
        # 物理树口径用 6000 条控制测试时长；六万条要求由无磁盘 IO 的清单口径完整覆盖
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = run_demo.main(physical_n=6000, manifest_n=60_000)
            captured = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "_demoout.txt")
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(captured)
        self.assertEqual(rc, 0, msg="端到端演示存在失败项，详见 _demoout.txt 与 demo-out/demo-report.json")
        self.assertIn("[7b] 六万条清单口径", captured)


if __name__ == "__main__":
    unittest.main()
