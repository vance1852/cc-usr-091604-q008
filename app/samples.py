"""样本监管领域的最小起点。"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Sample:
    """保存样本条码和采样批次。"""

    barcode: str
    batch: str


class CustodyService:
    """提供监管链服务的基础健康状态。"""

    def health(self) -> dict[str, str]:
        return {"service": "custody", "status": "ok"}

