"""监管链领域模型：角色、状态机、事件类型。

所有枚举都是 ``str`` 枚举，直接落库到 SQLite，保证重启后可回放。
"""

from __future__ import annotations

import enum


class Role(str, enum.Enum):
    """参与监管链的四类角色。"""

    SAMPLING_OFFICER = "SAMPLING_OFFICER"      # 采样官
    COURIER = "COURIER"                        # 运输人员
    LAB_TECHNICIAN = "LAB_TECHNICIAN"          # 实验室人员
    COMPLIANCE_OFFICER = "COMPLIANCE_OFFICER"  # 合规主管


class SampleStatus(str, enum.Enum):
    """样本生命周期状态机。"""

    SEALED = "SEALED"                        # 已采样并加封
    IN_TRANSIT = "IN_TRANSIT"                # 已交出，运输途中
    IN_CUSTODY = "IN_CUSTODY"                # 已被接收方保管
    QUARANTINED = "QUARANTINED"              # 异常隔离中，等待合规裁决
    SPLIT = "SPLIT"                          # 已拆分为 A/B 子瓶（父瓶终态）
    ANALYZED = "ANALYZED"                    # 实验室已出结果
    RETEST_AUTHORIZED = "RETEST_AUTHORIZED"  # 已授权复检
    CONDEMNED = "CONDEMNED"                  # 合规判定作废，待销毁
    DESTROYED = "DESTROYED"                  # 已销毁（终态）


class EventType(str, enum.Enum):
    """追加到事件链上的事件类型。"""

    CUSTODIAN_ENROLLED = "CUSTODIAN_ENROLLED"
    ATHLETE_REGISTERED = "ATHLETE_REGISTERED"
    BATCH_CREATED = "BATCH_CREATED"
    SAMPLE_REGISTERED = "SAMPLE_REGISTERED"
    SAMPLE_SEALED = "SAMPLE_SEALED"
    TEMPERATURE_RECORDED = "TEMPERATURE_RECORDED"
    TRANSFER_OUT = "TRANSFER_OUT"   # 交出方发运
    TRANSFER_IN = "TRANSFER_IN"     # 接收方签收
    ANOMALY_REPORTED = "ANOMALY_REPORTED"
    QUARANTINE_RESOLVED = "QUARANTINE_RESOLVED"
    SAMPLE_SPLIT = "SAMPLE_SPLIT"
    RESULT_RECORDED = "RESULT_RECORDED"
    RETEST_AUTHORIZED = "RETEST_AUTHORIZED"
    SAMPLE_DESTROYED = "SAMPLE_DESTROYED"


class AnomalyType(str, enum.Enum):
    """可申报的异常类别。"""

    SEAL_MISMATCH = "SEAL_MISMATCH"                    # 封条编号不符
    TEMPERATURE_EXCURSION = "TEMPERATURE_EXCURSION"    # 冷链温度越限
    TIME_WINDOW_BREACH = "TIME_WINDOW_BREACH"          # 交接超时
    CONTAINER_DAMAGED = "CONTAINER_DAMAGED"            # 容器破损
    OTHER = "OTHER"


class QuarantineResolution(str, enum.Enum):
    """合规主管对隔离样本的裁决方式。"""

    RELEASE = "RELEASE"    # 解除隔离，恢复保管
    RESEAL = "RESEAL"      # 凭授权文件重新加封（唯一合法的换封途径）
    CONDEMN = "CONDEMN"    # 判定作废


#: 允许的角色交接路径（交出方角色 -> 接收方角色）。
#: 合规主管作为监管方可以与任何角色交接（用于隔离样本的接管与返还）。
ALLOWED_HANDOVERS: frozenset[tuple[Role, Role]] = frozenset(
    {
        (Role.SAMPLING_OFFICER, Role.COURIER),
        (Role.SAMPLING_OFFICER, Role.LAB_TECHNICIAN),
        (Role.COURIER, Role.COURIER),
        (Role.COURIER, Role.LAB_TECHNICIAN),
        (Role.LAB_TECHNICIAN, Role.LAB_TECHNICIAN),
    }
    | {(r, Role.COMPLIANCE_OFFICER) for r in Role}
    | {(Role.COMPLIANCE_OFFICER, r) for r in Role}
)
