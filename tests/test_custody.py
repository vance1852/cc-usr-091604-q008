"""监管链服务的端到端行为测试。

覆盖：角色交接与越权拒绝、签名/时间窗/封条/冷链校验、异常隔离、
A/B 父子关系、授权复检与销毁、脱敏、幂等重试、重复扫描、跨时区、
重启重放与哈希链防篡改。
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.models import (
    Actor,
    AnomalyKind,
    Athlete,
    AuthzError,
    AuthorizationRequiredError,
    ColdChainError,
    DuplicateBarcodeError,
    IdempotencyConflict,
    IntegrityError,
    QuarantineError,
    Role,
    SealError,
    SignatureError,
    Status,
    TimeWindowError,
    ValidationError,
    sign_handover,
)
from app.service import CustodyService

# 决赛晚 18:00（北京时区）采样；运输跨多个时区。
T0 = datetime(2026, 9, 18, 18, 0, tzinfo=timezone(timedelta(hours=8)))
ATHLETE = Athlete(name="张三", id_number="110101199001011234", nationality="CHN", sport="athletics")
BATCH = "FINAL-2026-09-18"


def t(hours: float = 0, minutes: int = 0) -> datetime:
    return T0 + timedelta(hours=hours, minutes=minutes)


def tz(hours: float, offset_hours: int) -> datetime:
    """采样后 hours 小时、以 offset_hours 时区表示的同一绝对时刻。"""

    instant = T0 + timedelta(hours=hours)
    return instant.astimezone(timezone(timedelta(hours=offset_hours)))


def temps(*offsets_hours: float, temp_c: float = 6.0) -> list[dict]:
    return [{"at": t(h), "temp_c": temp_c} for h in offsets_hours]


class CustodyFixture:
    def __init__(self, path: str | None = None) -> None:
        self.svc = CustodyService(path)
        # 用户已存在时（重启重放场景）保持同一身份，不重复登记。
        for uid, role, key, name in [
            ("dco-1", Role.DCO, "key-dco", "采样官甲"),
            ("car-1", Role.CARRIER, "key-car", "运输员乙"),
            ("lab-1", Role.LAB, "key-lab", "实验室丙"),
            ("comp-1", Role.COMPLIANCE, "key-comp", "合规主管丁"),
        ]:
            if uid not in self.svc.projection.users:
                self.svc.register_user(uid, role, key, name)
        self.dco = Actor("dco-1", Role.DCO, "key-dco")
        self.car = Actor("car-1", Role.CARRIER, "key-car")
        self.lab = Actor("lab-1", Role.LAB, "key-lab")
        self.comp = Actor("comp-1", Role.COMPLIANCE, "key-comp")

    def register(self, barcode: str = "S-001", seal: str = "SEAL-001", **kw) -> dict:
        return self.svc.register_sample(
            self.dco, barcode, BATCH, ATHLETE, seal, t(0), **kw
        )

    def to_carrier(self, barcode: str = "S-001", seal: str = "SEAL-001", at=None,
                   signature: str | None = None, temps_=None, **kw):
        at = at or t(0.5)
        signature = signature if signature is not None else sign_handover(
            self.dco, barcode, at, "car-1"
        )
        return self.svc.handover(
            self.dco, barcode, "car-1", at, signature, seal,
            temperatures=temps_, **kw
        )

    def to_lab(self, barcode: str = "S-001", seal: str = "SEAL-001", at=None,
               signature: str | None = None, temps_=None, **kw):
        at = at or t(6)
        signature = signature if signature is not None else sign_handover(
            self.car, barcode, at, "lab-1"
        )
        temps_ = temps_ if temps_ is not None else temps(1, 2.5, 4, 5.5)
        return self.svc.handover(
            self.car, barcode, "lab-1", at, signature, seal,
            temperatures=temps_, **kw
        )

    def full_to_lab(self, barcode: str = "S-001", seal: str = "SEAL-001"):
        self.register(barcode, seal)
        self.to_carrier(barcode, seal)
        self.to_lab(barcode, seal)


class HappyPathTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CustodyFixture()

    def test_register_to_lab_split_retest_destroy(self):
        fx = self.fx
        fx.full_to_lab("S-100", "SEAL-100")
        st = fx.svc.status(fx.lab, "S-100")
        self.assertEqual(st["status"], Status.AT_LAB.value)
        self.assertEqual(st["custodian"], "lab-1")
        self.assertEqual(st["handover_count"], 2)

        # 拆分 A/B 瓶
        split = fx.svc.split_aliquots(fx.lab, "S-100", "A-1", "B-1", t(7))
        self.assertEqual(split["children"], {"A": "S-100-A", "B": "S-100-B"})
        parent = fx.svc.status(fx.comp, "S-100")
        self.assertEqual(parent["status"], Status.SPLIT.value)
        self.assertEqual(parent["children"], {"S-100-A": "A", "S-100-B": "B"})
        b_view = fx.svc.status(fx.lab, "S-100-B")
        self.assertEqual(b_view["parent_barcode"], "S-100")
        self.assertEqual(b_view["aliquot_type"], "B")

        # B 瓶复检必须授权
        fx.svc.grant_authorization(fx.comp, "AUTH-R-1", "S-100-B", "retest", t(7.2))
        r = fx.svc.retest(fx.lab, "S-100-B", "AUTH-R-1", t(7.5))
        self.assertEqual(r["status"], Status.RETESTED.value)

        # A 瓶销毁必须授权
        fx.svc.grant_authorization(fx.comp, "AUTH-D-1", "S-100-A", "destroy", t(8))
        d = fx.svc.destroy(fx.lab, "S-100-A", "AUTH-D-1", t(8.2))
        self.assertEqual(d["status"], Status.DESTROYED.value)

    def test_cross_timezone_handover(self):
        # 交接时刻分别用北京、迪拜、UTC 表示，绝对时刻一致即可通过。
        fx = self.fx
        fx.register("S-200", "SEAL-200")
        fx.svc.handover(
            fx.dco, "S-200", "car-1", tz(0.5, 4),
            sign_handover(fx.dco, "S-200", tz(0.5, 4), "car-1"),
            "SEAL-200",
        )
        fx.svc.handover(
            fx.car, "S-200", "lab-1", tz(6, 0),
            sign_handover(fx.car, "S-200", tz(6, 0), "lab-1"),
            "SEAL-200",
            temperatures=temps(1, 2.5, 4, 5.5),
        )
        self.assertEqual(fx.svc.status(fx.lab, "S-200")["status"], Status.AT_LAB.value)

    def test_naive_timestamp_rejected(self):
        fx = self.fx
        fx.register("S-201", "SEAL-201")
        with self.assertRaises(ValidationError):
            fx.svc.handover(
                fx.dco, "S-201", "car-1",
                datetime(2026, 9, 18, 18, 30),  # 无时区
                "sig", "SEAL-201",
            )


class UnauthorizedHandoverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CustodyFixture()
        self.fx.register("S-001", "SEAL-001")

    def test_non_custodian_cannot_handover(self):
        # 样本还在采样官手里，运输员不能发起交接
        with self.assertRaises(AuthzError):
            self.fx.svc.handover(
                self.fx.car, "S-001", "lab-1", t(1),
                sign_handover(self.fx.car, "S-001", t(1), "lab-1"),
                "SEAL-001",
            )

    def test_skip_carrier_rejected(self):
        # 采样官直接交给实验室：越级交接
        with self.assertRaises(AuthzError):
            self.fx.svc.handover(
                self.fx.dco, "S-001", "lab-1", t(0.5),
                sign_handover(self.fx.dco, "S-001", t(0.5), "lab-1"),
                "SEAL-001",
            )

    def test_lab_cannot_receive_twice(self):
        fx = self.fx
        fx.to_carrier()
        fx.to_lab()
        # 实验室是链路终点，不能再交回运输（反向交接）
        with self.assertRaises(AuthzError):
            fx.svc.handover(
                fx.lab, "S-001", "car-1", t(7),
                sign_handover(fx.lab, "S-001", t(7), "car-1"),
                "SEAL-001",
            )

    def test_wrong_signature_rejected(self):
        with self.assertRaises(SignatureError):
            self.fx.to_carrier(signature="deadbeef")

    def test_signature_bound_to_fields(self):
        # 签名绑定接收方：签给运输员的签名不能用于交给别人
        self.fx.svc.register_user("car-2", Role.CARRIER, "key-car2")
        sig = sign_handover(self.fx.dco, "S-001", t(0.5), "car-1")
        with self.assertRaises((SignatureError, AuthzError)):
            self.fx.svc.handover(
                self.fx.dco, "S-001", "car-2", t(0.5), sig, "SEAL-001"
            )

    def test_failed_handover_changes_nothing(self):
        with self.assertRaises(SignatureError):
            self.fx.to_carrier(signature="bad")
        st = self.fx.svc.status(self.fx.dco, "S-001")
        self.assertEqual(st["custodian"], "dco-1")
        self.assertEqual(st["handover_count"], 0)
        self.assertEqual(st["status"], Status.REGISTERED.value)


class SealTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CustodyFixture()
        self.fx.register("S-001", "SEAL-001")

    def test_seal_mismatch_blocks_handover(self):
        # 交接箱封条编号与采样表不一致：拒绝交接，原样不变
        with self.assertRaises(SealError):
            self.fx.to_carrier(seal="SEAL-999")
        st = self.fx.svc.status(self.fx.dco, "S-001")
        self.assertEqual(st["seal"], "SEAL-001")
        self.assertEqual(st["custodian"], "dco-1")

    def test_illegal_seal_replacement_rejected(self):
        # 正常流转中任何角色都不能换封条，合规主管也不行
        with self.assertRaises(Exception):
            self.fx.svc.replace_seal(
                self.fx.comp, "S-001", "SEAL-NEW", t(1),
                authorization_no="AUTH-X", witness_id="lab-1",
            )
        # 运输员更不行
        with self.assertRaises(AuthzError):
            self.fx.svc.replace_seal(
                self.fx.car, "S-001", "SEAL-NEW", t(1),
                authorization_no="AUTH-X", witness_id="lab-1",
            )

    def test_authorized_seal_replace_goes_through_quarantine(self):
        fx = self.fx
        fx.to_carrier()
        fx.svc.report_anomaly(
            fx.car, "S-001", AnomalyKind.SEAL_BROKEN, "运输途中封条破损", t(2)
        )
        # 隔离中没有授权不能换
        with self.assertRaises(AuthorizationRequiredError):
            fx.svc.replace_seal(fx.comp, "S-001", "SEAL-NEW", t(2.2),
                                 "NOPE", witness_id="dco-1")
        fx.svc.grant_authorization(fx.comp, "AUTH-S-1", "S-001", "seal_replace", t(2.1))
        # 自证自见不允许
        with self.assertRaises(AuthzError):
            fx.svc.replace_seal(fx.comp, "S-001", "SEAL-NEW", t(2.3),
                                 "AUTH-S-1", witness_id="comp-1")
        out = fx.svc.replace_seal(fx.comp, "S-001", "SEAL-NEW", t(2.4),
                                  "AUTH-S-1", witness_id="dco-1")
        self.assertEqual(out["old_seal"], "SEAL-001")
        # 授权单已一次性核销：隔离尚未解除时复用同一授权单也被拒绝
        with self.assertRaises(AuthorizationRequiredError):
            fx.svc.replace_seal(fx.comp, "S-001", "SEAL-NEW2", t(2.5),
                                "AUTH-S-1", witness_id="dco-1")
        released = fx.svc.release_quarantine(fx.comp, "S-001", t(2.6),
                                             "封条破损系包装挤压，授权重封后放行")
        # 隔离发生在运输途中：解除后必须恢复 in_transit 而不是错误地变成 at_lab
        self.assertEqual(released["status"], Status.IN_TRANSIT.value)
        self.assertEqual(fx.svc.status(fx.car, "S-001")["status"],
                         Status.IN_TRANSIT.value)
        # 解除隔离后无授权不得再换封条
        with self.assertRaises(QuarantineError):
            fx.svc.replace_seal(fx.comp, "S-001", "SEAL-NEW3", t(2.7),
                                "AUTH-S-1", witness_id="dco-1")
        # 用新封条继续正常送达
        fx.to_lab(seal="SEAL-NEW", at=t(5),
                  signature=sign_handover(fx.car, "S-001", t(5), "lab-1"))
        self.assertEqual(fx.svc.status(fx.lab, "S-001")["seal"], "SEAL-NEW")


class TimeWindowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CustodyFixture()
        self.fx.register("S-001", "SEAL-001")

    def test_late_carrier_to_lab_rejected(self):
        fx = self.fx
        fx.to_carrier()
        with self.assertRaises(TimeWindowError):
            fx.to_lab(at=t(50))  # 超过 48 小时运输窗

    def test_timestamp_regression_rejected(self):
        # 第二段交接早于第一段（时间戳倒退）
        fx = self.fx
        fx.to_carrier(at=t(0.5))
        with self.assertRaises(TimeWindowError):
            fx.to_lab(at=t(0.4))


class ColdChainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CustodyFixture()
        self.fx.register("S-001", "SEAL-001")
        self.fx.to_carrier()

    def test_missing_temperature_record_rejected(self):
        with self.assertRaises(ColdChainError):
            self.fx.to_lab(temps_=[])

    def test_out_of_range_temperature_rejected(self):
        bad = temps(1, 2.5, 4) + [{"at": t(5.5), "temp_c": 14.5}]
        with self.assertRaises(ColdChainError):
            self.fx.to_lab(temps_=bad)

    def test_temperature_gap_rejected(self):
        with self.assertRaises(ColdChainError):
            self.fx.to_lab(temps_=temps(1, 5))  # 1h -> 5h 间隔 4 小时，超过 3 小时

    def test_record_temperatures_then_handover(self):
        fx = self.fx
        fx.svc.record_temperatures(fx.car, "S-001", temps(1, 2.5, 4))
        fx.to_lab(temps_=temps(5.5))


class QuarantineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CustodyFixture()
        self.fx.full_to_lab("S-700", "SEAL-700")
        self.fx.svc.split_aliquots(self.fx.lab, "S-700", "A-7", "B-7", t(6.2))

    def test_anomaly_quarantines_family_and_freezes_flow(self):
        fx = self.fx
        out = fx.svc.report_anomaly(
            fx.lab, "S-700-A", AnomalyKind.SEAL_MISMATCH,
            "交接箱封条编号与采样表不一致", t(6.5)
        )
        # 父子同批 A/B 瓶全部隔离
        self.assertEqual(set(out["quarantined"]), {"S-700", "S-700-A", "S-700-B"})
        for bc in out["quarantined"]:
            self.assertEqual(fx.svc.status(fx.lab, bc)["status"], Status.QUARANTINED.value)
        # 隔离期间复检/交接全部冻结
        fx.svc.grant_authorization(fx.comp, "AUTH-Q", "S-700-B", "retest", t(6.6))
        with self.assertRaises(Exception):
            fx.svc.retest(fx.lab, "S-700-B", "AUTH-Q", t(6.7))

    def test_only_compliance_can_release(self):
        fx = self.fx
        fx.svc.report_anomaly(fx.lab, "S-700", AnomalyKind.PAPERWORK, "采样表缺页", t(6.4))
        with self.assertRaises(AuthzError):
            fx.svc.release_quarantine(fx.lab, "S-700", t(6.6), "实验室自行放行不允许")
        out = fx.svc.release_quarantine(
            fx.comp, "S-700", t(6.8), "补齐采样表副页，核对封条无误，解除隔离"
        )
        # 解除隔离后恢复到隔离前的 split 状态，异常记录仍然保留
        self.assertEqual(out["status"], Status.SPLIT.value)
        self.assertEqual(fx.svc.status(fx.comp, "S-700")["status"], Status.SPLIT.value)
        # 原始记录仍然在：异常申报没有被删除或覆盖
        audit = fx.svc.audit_export(fx.comp, "S-700")
        kinds = [e["payload"]["type"] for e in audit["events"]]
        self.assertIn("anomaly_reported", kinds)
        self.assertIn("quarantined", kinds)
        self.assertIn("quarantine_released", kinds)


class AuthorizationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CustodyFixture()
        self.fx.full_to_lab("S-800", "SEAL-800")
        self.fx.svc.split_aliquots(self.fx.lab, "S-800", "A-8", "B-8", t(6.2))

    def test_retest_without_authorization_rejected(self):
        with self.assertRaises(AuthorizationRequiredError):
            self.fx.svc.retest(self.fx.lab, "S-800-B", "NO-AUTH", t(7))

    def test_only_b_bottle_can_be_retested(self):
        fx = self.fx
        fx.svc.grant_authorization(fx.comp, "RA", "S-800-A", "retest", t(6.6))
        with self.assertRaises(ValidationError):
            fx.svc.retest(fx.lab, "S-800-A", "RA", t(7))

    def test_authorization_single_use_and_expiry(self):
        fx = self.fx
        fx.svc.grant_authorization(fx.comp, "RB", "S-800-B", "retest", t(6.6))
        fx.svc.retest(fx.lab, "S-800-B", "RB", t(7))
        with self.assertRaises(AuthorizationRequiredError):
            fx.svc.retest(fx.lab, "S-800-B", "RB", t(7.5))

        fx.svc.grant_authorization(
            fx.comp, "RC", "S-800-B", "retest", t(6.6), expires_at=t(6.9)
        )
        with self.assertRaises(AuthorizationRequiredError):
            fx.svc.retest(fx.lab, "S-800-B", "RC", t(7.2))

    def test_authorization_target_and_purpose_must_match(self):
        fx = self.fx
        fx.svc.grant_authorization(fx.comp, "RD", "S-800-A", "destroy", t(6.6))
        with self.assertRaises(AuthorizationRequiredError):
            fx.svc.retest(fx.lab, "S-800-B", "RD", t(7))  # 用途/对象都不符

    def test_lab_cannot_grant_authorization(self):
        with self.assertRaises(AuthzError):
            self.fx.svc.grant_authorization(
                self.fx.lab, "RX", "S-800-B", "retest", t(6.6)
            )


class MaskingAndAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CustodyFixture()
        self.fx.full_to_lab("S-001", "SEAL-001")

    def test_pii_masked_for_non_compliance(self):
        for actor in (self.fx.dco, self.fx.car, self.fx.lab):
            view = self.fx.svc.status(actor, "S-001")["athlete"]
            self.assertTrue(view["masked"])
            self.assertNotIn("张三", view["name"])
            self.assertTrue(view["id_number"].startswith("****"))
            self.assertNotIn("110101", view["id_number"])
        full = self.fx.svc.status(self.fx.comp, "S-001")["athlete"]
        self.assertEqual(full["name"], "张三")
        self.assertEqual(full["id_number"], "110101199001011234")

    def test_audit_export_compliance_only(self):
        with self.assertRaises(AuthzError):
            self.fx.svc.audit_export(self.fx.lab, "S-001")
        audit = self.fx.svc.audit_export(self.fx.comp, "S-001")
        self.assertTrue(audit["verified"])
        types_ = [e["payload"]["type"] for e in audit["events"]]
        self.assertEqual(types_[0], "sample_registered")
        self.assertIn("handover", types_)


class IdempotencyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CustodyFixture()
        self.fx.register("S-001", "SEAL-001")

    def test_offline_retry_replays_first_handover(self):
        fx = self.fx
        at = t(0.5)
        sig = sign_handover(fx.dco, "S-001", at, "car-1")
        kw = dict(temperatures=None, idem_key="client-handover-1")
        first = fx.svc.handover(fx.dco, "S-001", "car-1", at, sig, "SEAL-001", **kw)
        # 断网：客户端没收到响应，原样重试（此时保管人已是运输员）
        retry = fx.svc.handover(fx.dco, "S-001", "car-1", at, sig, "SEAL-001", **kw)
        self.assertTrue(retry["deduped"])
        self.assertEqual(retry["event_seq"], first["event_seq"])
        self.assertEqual(fx.svc.status(fx.car, "S-001")["handover_count"], 1)

    def test_same_idem_key_different_body_rejected(self):
        fx = self.fx
        fx.svc.register_sample(fx.dco, "S-301", BATCH, ATHLETE, "X1", t(0),
                               idem_key="token-1")
        with self.assertRaises(IdempotencyConflict):
            fx.svc.register_sample(fx.dco, "S-302", BATCH, ATHLETE, "X2", t(0),
                                   idem_key="token-1")

    def test_duplicate_barcode_scan_deduped(self):
        fx = self.fx
        first = fx.svc.scan(fx.dco, "S-001", BATCH, ATHLETE, "SEAL-001", t(0))
        self.assertTrue(first["deduped"])
        # 重复扫描且封条不一致 -> 拒绝（不能借重复扫描改写封条）
        with self.assertRaises(SealError):
            fx.svc.scan(fx.dco, "S-001", BATCH, ATHLETE, "SEAL-FORGED", t(0))

    def test_new_barcode_scan_registers(self):
        out = self.fx.svc.scan(self.fx.dco, "S-500", BATCH, ATHLETE, "SL-500", t(0))
        self.assertFalse(out["deduped"])
        self.assertEqual(self.fx.svc.status(self.fx.dco, "S-500")["seal"], "SL-500")

    def test_explicit_duplicate_register_rejected(self):
        with self.assertRaises(DuplicateBarcodeError):
            self.fx.register("S-001", "SEAL-001")

    def test_anomaly_retry_keeps_single_report(self):
        fx = self.fx
        fx.to_carrier()
        a1 = fx.svc.report_anomaly(
            fx.car, "S-001", AnomalyKind.TEMP_BREACH, "超温", t(2),
            idem_key="anm-1",
        )
        a2 = fx.svc.report_anomaly(
            fx.car, "S-001", AnomalyKind.TEMP_BREACH, "超温", t(2),
            idem_key="anm-1",
        )
        self.assertTrue(a2["deduped"])
        self.assertEqual(a1["report_id"], a2["report_id"])
        st = fx.svc.status(fx.comp, "S-001")
        self.assertEqual(st["open_anomalies"], [a1["report_id"]])


class BatchHandoverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = CustodyFixture()
        for bc, seal in [("S-1", "K-1"), ("S-2", "K-2"), ("S-3", "K-3")]:
            self.fx.register(bc, seal)

    def test_partial_batch_success(self):
        at = t(0.5)
        items = []
        for bc, seal in [("S-1", "K-1"), ("S-2", "WRONG"), ("S-3", "K-3")]:
            items.append({
                "barcode": bc,
                "to_id": "car-1",
                "at": at,
                "signature": sign_handover(self.fx.dco, bc, at, "car-1"),
                "presented_seal": seal,
            })
        result = self.fx.svc.batch_handover(self.fx.dco, items, idem_prefix="batch-1")
        self.assertEqual({r["barcode"] for r in result["accepted"]}, {"S-1", "S-3"})
        self.assertEqual(len(result["rejected"]), 1)
        self.assertEqual(result["rejected"][0]["error"], "SealError")
        # 失败项原样保留
        self.assertEqual(self.fx.svc.status(self.fx.dco, "S-2")["custodian"], "dco-1")

    def test_batch_retry_is_idempotent(self):
        at = t(0.5)
        items = [{
            "barcode": "S-1", "to_id": "car-1", "at": at,
            "signature": sign_handover(self.fx.dco, "S-1", at, "car-1"),
            "presented_seal": "K-1",
        }]
        r1 = self.fx.svc.batch_handover(self.fx.dco, items, idem_prefix="batch-x")
        r2 = self.fx.svc.batch_handover(self.fx.dco, items, idem_prefix="batch-x")
        self.assertEqual(len(r2["accepted"]), 1)
        self.assertTrue(r2["accepted"][0]["deduped"])
        self.assertEqual(r1["accepted"][0]["event_seq"], r2["accepted"][0]["event_seq"])


class PersistenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "custody.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_restart_replays_full_chain(self):
        fx = CustodyFixture(str(self.path))
        fx.full_to_lab("S-001", "SEAL-001")
        fx.svc.split_aliquots(fx.lab, "S-001", "A-1", "B-1", t(6.3))
        head_before = fx.svc.store.head_hash
        size_before = fx.svc.store.size

        # 全新进程视角：重新打开同一个日志文件
        revived = CustodyFixture(str(self.path))
        self.assertEqual(revived.svc.store.head_hash, head_before)
        self.assertEqual(revived.svc.store.size, size_before)
        st = revived.svc.status(revived.lab, "S-001")
        self.assertEqual(st["status"], Status.SPLIT.value)
        self.assertEqual(st["custodian"], "lab-1")
        self.assertEqual(revived.svc.status(revived.lab, "S-001-B")["aliquot_type"], "B")
        # 重启后链路仍可继续，且序号不重复
        revived.svc.grant_authorization(revived.comp, "AU", "S-001-B", "retest", t(7))
        revived.svc.retest(revived.lab, "S-001-B", "AU", t(7.2))

        # restart() 也会重新校验并重放
        revived.svc.restart()
        revived.svc.verify_integrity()
        self.assertEqual(revived.svc.status(revived.comp, "S-001-B")["status"],
                         Status.RETESTED.value)

    def test_tampered_history_is_detected_on_load(self):
        fx = CustodyFixture(str(self.path))
        fx.full_to_lab("S-001", "SEAL-001")
        del fx

        # 事后篡改原始记录中的封条编号（模拟有人直接改日志）
        raw = self.path.read_text(encoding="utf-8")
        tampered = raw.replace("SEAL-001", "SEAL-FORGED", 1)
        self.assertNotEqual(raw, tampered)
        self.path.write_text(tampered, encoding="utf-8")

        with self.assertRaises(IntegrityError):
            CustodyService(str(self.path))

    def test_replay_state_matches_live_state(self):
        fx = CustodyFixture(str(self.path))
        fx.full_to_lab("S-001", "SEAL-001")
        fx.svc.report_anomaly(fx.car, "S-001", AnomalyKind.OTHER, "复测用异常", t(6.1),
                              quarantine=False)
        live = fx.svc.audit_export(fx.comp)
        revived = CustodyFixture(str(self.path))
        again = revived.svc.audit_export(revived.comp)
        self.assertEqual(
            [e["hash"] for e in live["events"]],
            [e["hash"] for e in again["events"]],
        )
        self.assertEqual(
            revived.svc.status(revived.comp, "S-001"),
            fx.svc.status(fx.comp, "S-001"),
        )


if __name__ == "__main__":
    unittest.main()
