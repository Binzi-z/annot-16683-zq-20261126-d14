"""全部自定义异常集中定义。"""


class QuarPromError(Exception):
    """基类。"""


class RootAliasError(QuarPromError):
    """来源/目标路径通过别名（junction、符号链接、8.3、.. 等）偷换控制根。"""


class ApprovalError(QuarPromError):
    """审批记录无效（签名、控制人数量、根绑定、摘要不匹配等）。"""


class LogIntegrityError(QuarPromError):
    """决定日志哈希链断裂或被篡改。"""


class SegmentedWriteError(QuarPromError):
    """分段写入在最后一段失败（故障注入或真实 IO 错误）。"""


class PromotionError(QuarPromError):
    """晋升流程被安全策略拒绝。"""


class ViewReplayError(QuarPromError):
    """旧版本视图重放失败（清单与内容寻址块不一致）。"""
