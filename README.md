# 样本监管链服务

赛事反兴奋剂样本（尿样）监管链的 Python 参考实现。覆盖决赛后从采样、加封、
运输、实验室签收到 A/B 拆分、复检、销毁的完整保管链路，任何一步对不上
（封条编号不符、交接超时、温度越限）都会进入隔离流程，原始记录不可修改。

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

## 设计要点

- **只追加事件日志**：所有动作都是带序号的事件，落库后不可修改；
  每个事件链接前一事件哈希（SHA-256）并由操作人个人密钥签名
  （HMAC-SHA256），篡改任何历史记录都会被 `verify_chain()` 发现。
- **交接三重验证**：每次签收必须验证前一环签名、交接时间窗
  （默认 36 小时，可配置）和封条状态；封条不符自动进入隔离流程。
- **异常只进隔离、不改原始记录**：异常申报 / 自动隔离都是新事件，
  只有合规主管能凭授权依据裁决（解除 / 重新加封 / 作废）。
  `RESEAL` 是更换封条的唯一合法途径，旧封条永久留痕。
- **A/B 拆分保持父子关系**：父瓶拆分后为终态，子瓶独立成链，
  审计导出父样本时自动包含全部后代。
- **销毁 / 复检必须留授权依据**：`authorization_ref` 强制非空并写入事件。
- **幂等**：扫描录入按条码去重；所有写操作支持幂等键，断网重试、
  重复扫码不会产生重复记录；同一幂等键携带不同内容会报冲突。
- **跨时区**：时间戳强制携带时区，统一按 UTC 存储与比较；
  拒绝朴素（无时区）时间。
- **重启可回放**：SQLite 持久化，服务打开时默认自动校验整条链。
- **按角色脱敏**：合规主管 / 采样官见完整身份；运输人员见掩码姓名
  与假名证件号；实验室只见假名编号（`ATH-xxxxxxxxxxxx`）。

## 角色

| 角色 | 权限 |
| --- | --- |
| `SAMPLING_OFFICER` 采样官 | 扫描录入、加封、交出、记录温度、申报异常 |
| `COURIER` 运输人员 | 签收 / 交出、运输途中记录温度、申报异常 |
| `LAB_TECHNICIAN` 实验室 | 签收、A/B 拆分、登记结果、申请复检 |
| `COMPLIANCE_OFFICER` 合规主管 | 隔离裁决（含 RESEAL）、销毁、审计导出全量身份 |

交接路径受控：采样官→运输/实验室，运输→运输/实验室，实验室→实验室，
合规主管可与任何角色交接（用于隔离样本接管）。

## 接口一览

| 接口 | 说明 |
| --- | --- |
| `enroll_custodian` / `register_athlete` / `create_batch` | 登记参与人 / 运动员 / 采样批次 |
| `scan_intake` | 扫描录入：登记样本并加封（按条码幂等） |
| `record_temperature` | 冷链温度记录，越限自动隔离 |
| `transfer_out` / `transfer_in` | 单个交接（发运 / 签收） |
| `batch_transfer_out` / `batch_transfer_in` | 批量交接（先整体预检再逐条追加） |
| `report_anomaly` / `resolve_quarantine` | 异常申报 / 隔离裁决 |
| `split_ab` / `record_result` / `request_retest` | 实验室拆分、结果、复检 |
| `destroy_sample` | 销毁（仅合规主管，需授权依据） |
| `get_sample` / `get_sample_history` / `get_batch_status` | 状态查询（按角色脱敏） |
| `export_audit` / `verify_export` / `verify_chain` | 审计导出与独立校验 |

## 最小示例

```python
from datetime import datetime, timedelta, timezone
from app import ChainOfCustodyService, Role

svc = ChainOfCustodyService("custody.db")
now = datetime.now(timezone.utc)

svc.enroll_custodian("officer-1", "王采样", Role.SAMPLING_OFFICER)
svc.enroll_custodian("courier-1", "赵运输", Role.COURIER)
svc.enroll_custodian("lab-1", "钱实验", Role.LAB_TECHNICIAN)
svc.enroll_custodian("comp-1", "孙合规", Role.COMPLIANCE_OFFICER)
svc.create_batch("officer-1", "BATCH-FINAL", description="决赛尿样批次")

# 扫描录入 + 加封（重复扫描同一条码是幂等的）
sample = svc.scan_intake(
    "officer-1", "BC-0001", batch_id="BATCH-FINAL",
    athlete={"athlete_id": "ATH-1", "name": "张伟",
             "team": "红队", "id_number": "110101199001011234"},
    seal_number="SEAL-0001",
    collected_at=now - timedelta(hours=3),
)
sid = sample["sample_id"]

# 交接：发运 → 签收（签收会验证前一环签名、时间窗、封条）
out = svc.transfer_out("officer-1", sid, "courier-1",
                       seal_number="SEAL-0001", at=now - timedelta(hours=2))
svc.transfer_in("courier-1", sid, out["event_id"],
                seal_number="SEAL-0001", at=now - timedelta(hours=1))

# 若签收时封条不符：自动进入隔离，只能由合规主管凭授权裁决
# svc.transfer_in(..., seal_number="SEAL-TAMPERED", ...)  # 抛 SealMismatch
# svc.resolve_quarantine("comp-1", sid, "RESEAL",
#                        authorization_ref="ADAMS-2026-091",
#                        new_seal_number="SEAL-NEW", at=now)

# 审计导出（合规角色可独立复算哈希与签名）
export = svc.export_audit(sample_id=sid, as_role=Role.COMPLIANCE_OFFICER)
assert svc.verify_export(export)
```

## 目录

- `app/custody.py`：监管链服务（业务规则、角色权限、隔离流程、脱敏）
- `app/store.py`：SQLite 追加式事件日志与物化状态
- `app/crypto.py`：哈希链、HMAC 签名、UTC 时间规范化
- `app/models.py`：角色、状态机、事件类型、交接路径
- `app/errors.py`：异常体系
- `app/samples.py`：最初的样本基础对象（保留）
- `tests/`：36 个行为测试（越权交接、非法换封、幂等、跨时区、重启、篡改检测等）

> 说明：签名密钥在本参考实现中由服务签发并随库保存，生产环境应替换为
> HSM / KMS 托管的非对称密钥；`enroll_custodian` 视为可信开通步骤。
