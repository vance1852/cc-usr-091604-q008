"""监管链服务的异常体系。

所有业务异常都继承自 :class:`CustodyError`，调用方可以按类别捕获。
异常一旦抛出，已提交的监管链事件不受影响 —— 原始记录永不被修改。
"""


class CustodyError(Exception):
    """监管链服务所有异常的基类。"""


class NotFound(CustodyError):
    """引用的实体（样本 / 人员 / 批次 / 事件）不存在。"""


class ValidationError(CustodyError):
    """请求参数不合法（时间戳缺时区、必填字段为空等）。"""


class PermissionDenied(CustodyError):
    """角色或保管人身份不允许执行该操作（越权）。"""


class InvalidState(CustodyError):
    """样本当前状态不允许该操作（如已销毁、已拆分、不在运输中）。"""


class SealMismatch(CustodyError):
    """交接时出示的封条编号与登记封条不一致。

    抛出此异常前，服务已自动把样本置入隔离流程并留下不可篡改的
    异常事件记录。
    """

    def __init__(self, message: str, *, quarantine_event_id: str | None = None):
        super().__init__(message)
        self.quarantine_event_id = quarantine_event_id


class TimeWindowViolation(CustodyError):
    """交接超出允许的时间窗，或时间顺序非法。"""


class Conflict(CustodyError):
    """幂等键被复用但请求内容不一致（疑似重复录入冲突）。"""


class ChainIntegrityError(CustodyError):
    """事件链哈希或签名校验失败 —— 记录可能被篡改。"""
