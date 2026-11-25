"""quarprom —— 隔离区制品晋升允许区的本地安全机制模拟（仅 Python 3.12 标准库）。

模块划分：
  paths     原生 Windows 路径/重解析点/8.3 别名防御
  digest    SHA-256、HMAC、规范化 JSON
  approval  双控制人审批（绑定目标根、完整摘要、代号、来源别名）
  declog    仅追加哈希链决定日志
  views     内容寻址不可变版本视图（持续读者可重放旧视图）
  journal   先提交的撤销日志 + 分段写入器
  promoter  真实双线程 + Barrier 的晋升编排与故障注入
  recovery  重启后依据实际目录与决定日志对账
  checker   完全独立的事后检查器（不导入本包任何模块）
"""

__version__ = "1.0.0"
