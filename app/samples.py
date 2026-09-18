"""样本监管领域入口（向后兼容模块）。

历史起点只保留 ``Sample`` 与健康检查；完整监管链实现见
:mod:`app.service` / :mod:`app.models`，这里统一再导出。
"""

from dataclasses import dataclass

from .models import Actor, AnomalyKind, Athlete, Role, Status, sign_handover
from .service import CustodyService

__all__ = [
    "Sample",
    "CustodyService",
    "Actor",
    "Athlete",
    "Role",
    "Status",
    "AnomalyKind",
    "sign_handover",
]


@dataclass(frozen=True)
class Sample:
    """保存样本条码和采样批次。"""

    barcode: str
    batch: str
