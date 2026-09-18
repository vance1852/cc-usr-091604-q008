"""样本监管链服务测试。

证明点：
- 完整链路可回放（登记→加封→交接→拆分→结果→审计导出）
- 拒绝越权交接（非保管人 / 非法角色路径 / 非指定接收方）
- 拒绝非法封条替换（唯一合法途径是合规主管凭授权的 RESEAL）
- 断网重试与同一条码重复扫描的幂等性
- 跨时区运输的时间一致性
- 服务重启后链路完整、可继续追加
- 篡改历史事件会被链校验发现
"""

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.custody import ChainOfCustodyService
from app.errors import (
    ChainIntegrityError,
    Conflict,
    InvalidState,
    NotFound,
    PermissionDenied,
    SealMismatch,
    TimeWindowViolation,
    ValidationError,
)
from app.models import (
    AnomalyType,
    EventType,
    QuarantineResolution,
    Role,
    SampleStatus,
)

OFFICER = "officer-01"
OFFICER2 = "officer-02"
COURIER = "courier-01"
LAB = "lab-01"
COMPLIANCE = "comp-01"
BATCH = "BATCH-FINAL-2026"

ATHLETE = {
    "athlete_id": "ATH-0001",
    "name": "张伟",
    "team": "红队",
    "id_number": "110101199001011234",
}


class CustodyTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "custody.db")
        self.svc = ChainOfCustodyService(self.db)
        self.addCleanup(self._close_svc)
        self.now = datetime.now(timezone.utc)
        self.svc.enroll_custodian(OFFICER, "王采样", Role.SAMPLING_OFFICER)
        self.svc.enroll_custodian(OFFICER2, "李采样", Role.SAMPLING_OFFICER)
        self.svc.enroll_custodian(COURIER, "赵运输", Role.COURIER)
        self.svc.enroll_custodian(LAB, "钱实验", Role.LAB_TECHNICIAN)
        self.svc.enroll_custodian(COMPLIANCE, "孙合规", Role.COMPLIANCE_OFFICER)
        self.svc.create_batch(OFFICER, BATCH, description="决赛尿样批次")

    def _close_svc(self):
        if self.svc is not None:
            self.svc.close()

    def t(self, **kwargs):
        """基准时间：现在往前推，避免触碰未来偏移限制。"""
        return self.now - timedelta(**kwargs)

    def scan(self, barcode="BC-0001", seal="SEAL-0001", athlete_id="ATH-0001", at=None):
        athlete = dict(ATHLETE, athlete_id=athlete_id)
        return self.svc.scan_intake(
            OFFICER, barcode, batch_id=BATCH, athlete=athlete,
            seal_number=seal, collected_at=at or self.t(hours=3),
        )

    def deliver_to_lab(self, barcode="BC-0001", seal="SEAL-0001"):
        """走通 采样官→运输→实验室 的完整交接，返回 sample_id。"""
        view = self.scan(barcode, seal)
        sid = view["sample_id"]
        out1 = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number=seal,
                                     at=self.t(hours=2, minutes=30))
        self.svc.transfer_in(COURIER, sid, out1["event_id"], seal_number=seal,
                             at=self.t(hours=2))
        out2 = self.svc.transfer_out(COURIER, sid, LAB, seal_number=seal,
                                     at=self.t(minutes=90))
        self.svc.transfer_in(LAB, sid, out2["event_id"], seal_number=seal,
                             at=self.t(hours=1))
        return sid


class FullChainTest(CustodyTestCase):
    def test_full_chain_happy_path(self):
        sid = self.deliver_to_lab()

        # 实验室拆分为 A/B 瓶
        split = self.svc.split_ab(
            LAB, sid, barcode_a="BC-0001-A", barcode_b="BC-0001-B",
            seal_a="SEAL-A1", seal_b="SEAL-B1", at=self.t(minutes=50),
        )
        child_a, child_b = [c["sample_id"] for c in split["payload"]["children"]]

        # A 瓶出结果
        self.svc.record_result(LAB, child_a, "NEGATIVE", lab_reference="LAB-RPT-1",
                               at=self.t(minutes=40))

        # 状态与父子关系
        parent = self.svc.get_sample(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(parent["status"], SampleStatus.SPLIT.value)
        self.assertEqual(sorted(parent["children"]), sorted([child_a, child_b]))
        view_a = self.svc.get_sample(child_a, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(view_a["status"], SampleStatus.ANALYZED.value)
        self.assertEqual(view_a["parent_id"], sid)
        self.assertEqual(view_a["bottle"], "A")

        # 链校验与回放
        result = self.svc.verify_chain()
        self.assertTrue(result["hashes_valid"])
        history = self.svc.get_sample_history(sid, as_role=Role.COMPLIANCE_OFFICER)
        types = [e["event_type"] for e in history]
        self.assertEqual(
            types,
            [EventType.SAMPLE_REGISTERED.value, EventType.SAMPLE_SEALED.value,
             EventType.TRANSFER_OUT.value, EventType.TRANSFER_IN.value,
             EventType.TRANSFER_OUT.value, EventType.TRANSFER_IN.value,
             EventType.SAMPLE_SPLIT.value],
        )
        # 审计导出可独立复算
        export = self.svc.export_audit(sample_id=sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertTrue(self.svc.verify_export(export))
        exported_sample_ids = {s["sample_id"] for s in export["samples"]}
        self.assertEqual(exported_sample_ids, {sid, child_a, child_b})

    def test_temperature_log_during_transit(self):
        view = self.scan()
        sid = view["sample_id"]
        self.svc.record_temperature(OFFICER, sid, 4.5, recorded_at=self.t(hours=2, minutes=50))
        out = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=self.t(hours=2, minutes=30))
        # 运输途中由指定接收方（承运人）记录冷链温度
        res = self.svc.record_temperature(COURIER, sid, 5.0,
                                          recorded_at=self.t(hours=2, minutes=10))
        self.assertIsNone(res["quarantine_event"])
        self.svc.transfer_in(COURIER, sid, out["event_id"], seal_number="SEAL-0001",
                             at=self.t(hours=2))
        history = self.svc.get_sample_history(sid, as_role=Role.COMPLIANCE_OFFICER)
        temps = [e for e in history if e["event_type"] == EventType.TEMPERATURE_RECORDED.value]
        self.assertEqual(len(temps), 2)
        self.assertEqual(temps[1]["actor_id"], COURIER)

    def test_batch_status_query(self):
        self.scan("BC-1001", "SEAL-1001", athlete_id="ATH-1001")
        self.scan("BC-1002", "SEAL-1002", athlete_id="ATH-1002")
        status = self.svc.get_batch_status(BATCH, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(len(status["samples"]), 2)
        self.assertTrue(all(s["status"] == SampleStatus.SEALED.value
                            for s in status["samples"]))


class UnauthorizedHandoverTest(CustodyTestCase):
    def test_non_custodian_cannot_dispatch(self):
        sid = self.scan()["sample_id"]
        with self.assertRaises(PermissionDenied):
            self.svc.transfer_out(COURIER, sid, LAB, seal_number="SEAL-0001",
                                  at=self.t(hours=2))

    def test_unenrolled_actor_rejected(self):
        sid = self.scan()["sample_id"]
        with self.assertRaises(NotFound):
            self.svc.transfer_out("ghost", sid, COURIER, seal_number="SEAL-0001",
                                  at=self.t(hours=2))

    def test_illegal_role_path_rejected(self):
        sid = self.scan()["sample_id"]
        # 采样官 → 采样官 不在允许的交接路径上
        with self.assertRaises(PermissionDenied):
            self.svc.transfer_out(OFFICER, sid, OFFICER2, seal_number="SEAL-0001",
                                  at=self.t(hours=2))

    def test_lab_cannot_dispatch_to_courier(self):
        sid = self.deliver_to_lab()
        with self.assertRaises(PermissionDenied):
            self.svc.transfer_out(LAB, sid, COURIER, seal_number="SEAL-0001",
                                  at=self.t(minutes=30))

    def test_wrong_receiver_cannot_accept(self):
        sid = self.scan()["sample_id"]
        out = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=self.t(hours=2))
        # 实验室不是本次发运指定的接收方
        with self.assertRaises(PermissionDenied):
            self.svc.transfer_in(LAB, sid, out["event_id"], seal_number="SEAL-0001",
                                 at=self.t(hours=1))

    def test_non_officer_cannot_scan_intake(self):
        with self.assertRaises(PermissionDenied):
            self.svc.scan_intake(
                COURIER, "BC-X", batch_id=BATCH, athlete=ATHLETE,
                seal_number="SEAL-X", collected_at=self.t(hours=3),
            )

    def test_quarantined_sample_cannot_be_transferred(self):
        sid = self.scan()["sample_id"]
        self.svc.report_anomaly(OFFICER, sid, AnomalyType.CONTAINER_DAMAGED,
                                "外箱破损", at=self.t(hours=2, minutes=30))
        with self.assertRaises(InvalidState):
            self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                  at=self.t(hours=2))


class SealIntegrityTest(CustodyTestCase):
    def test_seal_mismatch_at_receive_goes_to_quarantine(self):
        sid = self.scan()["sample_id"]
        out = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=self.t(hours=2))
        with self.assertRaises(SealMismatch) as ctx:
            self.svc.transfer_in(COURIER, sid, out["event_id"],
                                 seal_number="SEAL-TAMPERED", at=self.t(hours=1))
        self.assertIsNotNone(ctx.exception.quarantine_event_id)
        sample = self.svc.get_sample(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(sample["status"], SampleStatus.QUARANTINED.value)
        # 登记封条未被改写
        self.assertEqual(sample["seal_number"], "SEAL-0001")

    def test_illegal_seal_replacement_rejected_and_legal_reseal_traced(self):
        sid = self.scan()["sample_id"]
        out = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=self.t(hours=2))
        with self.assertRaises(SealMismatch):
            self.svc.transfer_in(COURIER, sid, out["event_id"],
                                 seal_number="SEAL-TAMPERED", at=self.t(hours=1))

        # 非合规角色尝试换封 → 拒绝
        with self.assertRaises(PermissionDenied):
            self.svc.resolve_quarantine(
                LAB, sid, QuarantineResolution.RESEAL,
                authorization_ref="AUTH-1", new_seal_number="SEAL-NEW",
                at=self.t(minutes=50))
        # 合规主管缺少授权依据 → 拒绝
        with self.assertRaises(ValidationError):
            self.svc.resolve_quarantine(
                COMPLIANCE, sid, QuarantineResolution.RESEAL,
                authorization_ref="", new_seal_number="SEAL-NEW",
                at=self.t(minutes=50))

        # 唯一合法途径：合规主管凭授权文件 RESEAL
        self.svc.resolve_quarantine(
            COMPLIANCE, sid, QuarantineResolution.RESEAL,
            authorization_ref="ADAMS-RULING-2026-091", new_seal_number="SEAL-NEW",
            at=self.t(minutes=50))
        sample = self.svc.get_sample(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(sample["seal_number"], "SEAL-NEW")
        self.assertEqual(sample["status"], SampleStatus.IN_CUSTODY.value)

        # 旧封条从此失效：用旧封条交出 → 再次进入隔离
        with self.assertRaises(SealMismatch):
            self.svc.transfer_out(COURIER, sid, LAB, seal_number="SEAL-0001",
                                  at=self.t(minutes=40))
        self.svc.resolve_quarantine(
            COMPLIANCE, sid, QuarantineResolution.RELEASE,
            authorization_ref="ADAMS-RULING-2026-092", at=self.t(minutes=35))
        # 新封条可以正常交接
        out2 = self.svc.transfer_out(COURIER, sid, LAB, seal_number="SEAL-NEW",
                                     at=self.t(minutes=30))
        self.svc.transfer_in(LAB, sid, out2["event_id"], seal_number="SEAL-NEW",
                             at=self.t(minutes=20))

        # 原始记录保持原样：首条加封事件仍是旧封条，换封以新事件留痕
        history = self.svc.get_sample_history(sid, as_role=Role.COMPLIANCE_OFFICER)
        sealed = [e for e in history if e["event_type"] == EventType.SAMPLE_SEALED.value]
        self.assertEqual(sealed[0]["payload"]["seal_number"], "SEAL-0001")
        reseals = [e for e in history
                   if e["event_type"] == EventType.QUARANTINE_RESOLVED.value
                   and e["payload"]["resolution"] == "RESEAL"]
        self.assertEqual(reseals[0]["payload"]["old_seal"], "SEAL-0001")
        self.assertEqual(reseals[0]["payload"]["new_seal"], "SEAL-NEW")
        self.assertEqual(reseals[0]["payload"]["authorization_ref"],
                         "ADAMS-RULING-2026-091")
        self.assertTrue(self.svc.verify_chain())

    def test_seal_mismatch_at_dispatch_goes_to_quarantine(self):
        sid = self.scan()["sample_id"]
        with self.assertRaises(SealMismatch):
            self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-WRONG",
                                  at=self.t(hours=2))
        sample = self.svc.get_sample(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(sample["status"], SampleStatus.QUARANTINED.value)


class IdempotencyTest(CustodyTestCase):
    def test_duplicate_barcode_scan_is_idempotent(self):
        first = self.scan("BC-DUP", "SEAL-DUP")
        second = self.scan("BC-DUP", "SEAL-DUP")
        self.assertEqual(first["sample_id"], second["sample_id"])
        self.assertEqual(self.svc.store.count_events(first["sample_id"]), 2)

    def test_conflicting_rescan_rejected(self):
        self.scan("BC-DUP2", "SEAL-1")
        with self.assertRaises(Conflict):
            self.scan("BC-DUP2", "SEAL-DIFFERENT")

    def test_offline_retry_same_idempotency_key(self):
        sid = self.scan()["sample_id"]
        at = self.t(hours=2)
        ev1 = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=at, idempotency_key="retry-0001")
        ev2 = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=at, idempotency_key="retry-0001")
        self.assertEqual(ev1["event_id"], ev2["event_id"])
        outs = [e for e in self.svc.get_sample_history(sid, as_role=Role.COMPLIANCE_OFFICER)
                if e["event_type"] == EventType.TRANSFER_OUT.value]
        self.assertEqual(len(outs), 1)

    def test_idempotency_key_reuse_with_different_content_conflicts(self):
        sid = self.scan()["sample_id"]
        self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                              at=self.t(hours=2), idempotency_key="retry-0002")
        with self.assertRaises(Conflict):
            self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                  at=self.t(hours=1), idempotency_key="retry-0002")

    def test_receive_retry_is_idempotent(self):
        sid = self.scan()["sample_id"]
        out = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=self.t(hours=2))
        at = self.t(hours=1)
        ev1 = self.svc.transfer_in(COURIER, sid, out["event_id"],
                                   seal_number="SEAL-0001", at=at,
                                   idempotency_key="recv-0001")
        ev2 = self.svc.transfer_in(COURIER, sid, out["event_id"],
                                   seal_number="SEAL-0001", at=at,
                                   idempotency_key="recv-0001")
        self.assertEqual(ev1["event_id"], ev2["event_id"])


class CrossTimezoneTest(CustodyTestCase):
    def test_cross_timezone_handover_uses_utc(self):
        tz_cst = timezone(timedelta(hours=8))    # 北京
        tz_est = timezone(-timedelta(hours=5))   # 纽约
        collected = (self.now - timedelta(hours=3)).astimezone(tz_cst)
        dispatched = (self.now - timedelta(hours=2)).astimezone(tz_cst)
        received = (self.now - timedelta(hours=1, minutes=30)).astimezone(tz_est)

        view = self.scan(at=collected.isoformat())
        sid = view["sample_id"]
        out = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=dispatched.isoformat())
        # 签收时间用另一个时区表达，实际间隔 30 分钟，应在窗口内
        ev = self.svc.transfer_in(COURIER, sid, out["event_id"],
                                  seal_number="SEAL-0001", at=received.isoformat())
        self.assertTrue(ev["occurred_at"].endswith("+00:00"))
        self.assertTrue(out["occurred_at"].endswith("+00:00"))

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValidationError):
            self.svc.scan_intake(
                OFFICER, "BC-NAIVE", batch_id=BATCH, athlete=ATHLETE,
                seal_number="SEAL-N", collected_at=datetime(2026, 9, 18, 10, 0, 0),
            )

    def test_event_cannot_predate_previous_event(self):
        sid = self.scan()["sample_id"]
        with self.assertRaises(ValidationError):
            self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                  at=self.t(hours=4))  # 早于采样时间


class TimeWindowTest(CustodyTestCase):
    def test_transfer_window_breach_rejected(self):
        view = self.scan(at=self.t(hours=40))
        sid = view["sample_id"]
        out = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=self.t(hours=39))
        # 默认窗口 36 小时，39 小时后的签收必须拒绝
        with self.assertRaises(TimeWindowViolation):
            self.svc.transfer_in(COURIER, sid, out["event_id"],
                                 seal_number="SEAL-0001", at=self.t(minutes=30))


class RestartAndTamperTest(CustodyTestCase):
    def test_restart_preserves_chain_and_state(self):
        sid = self.scan()["sample_id"]
        out = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=self.t(hours=2))
        head_before = self.svc.verify_chain()["head"]
        self.svc.close()

        # 重启：自动校验整条链，状态可继续推进
        self.svc = ChainOfCustodyService(self.db)
        self.assertEqual(self.svc.verify_chain()["head"], head_before)
        sample = self.svc.get_sample(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(sample["status"], SampleStatus.IN_TRANSIT.value)
        self.svc.transfer_in(COURIER, sid, out["event_id"], seal_number="SEAL-0001",
                             at=self.t(hours=1))
        self.svc.close()

        self.svc = ChainOfCustodyService(self.db)
        sample = self.svc.get_sample(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(sample["status"], SampleStatus.IN_CUSTODY.value)
        self.assertEqual(sample["current_custodian"]["actor_id"], COURIER)

    def test_tampered_history_detected_on_open(self):
        sid = self.scan()["sample_id"]
        self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                              at=self.t(hours=2))
        self.svc.close()

        # 攻击者直接改写数据库里的历史事件
        conn = sqlite3.connect(self.db)
        conn.execute(
            "UPDATE events SET payload = ? WHERE event_type = 'SAMPLE_SEALED'",
            (json.dumps({"seal_number": "SEAL-FORGED"}, ensure_ascii=False),),
        )
        conn.commit()
        conn.close()

        with self.assertRaises(ChainIntegrityError):
            ChainOfCustodyService(self.db)  # 默认打开时校验
        self.svc = ChainOfCustodyService(self.db, verify_on_open=False)
        with self.assertRaises(ChainIntegrityError):
            self.svc.verify_chain()


class QuarantineFlowTest(CustodyTestCase):
    def test_anomaly_quarantine_and_release_preserve_original_records(self):
        sid = self.scan()["sample_id"]
        before = self.svc.get_sample_history(sid, as_role=Role.COMPLIANCE_OFFICER)
        hashes_before = [e["hash"] for e in before]

        self.svc.report_anomaly(OFFICER, sid, AnomalyType.TEMPERATURE_EXCURSION,
                                "冷藏箱温度探头读数 12°C", at=self.t(hours=2, minutes=30))
        sample = self.svc.get_sample(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(sample["status"], SampleStatus.QUARANTINED.value)

        # 隔离中禁止交接
        with self.assertRaises(InvalidState):
            self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                  at=self.t(hours=2))

        # 合规主管凭授权解除隔离
        self.svc.resolve_quarantine(
            COMPLIANCE, sid, QuarantineResolution.RELEASE,
            authorization_ref="ADAMS-RULING-2026-100", at=self.t(hours=1))
        sample = self.svc.get_sample(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(sample["status"], SampleStatus.IN_CUSTODY.value)

        # 原始事件一个未改，只是向后追加
        after = self.svc.get_sample_history(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual([e["hash"] for e in after[:len(hashes_before)]], hashes_before)
        self.assertGreater(len(after), len(before))

        # 解除隔离后交接恢复
        out = self.svc.transfer_out(OFFICER, sid, COURIER, seal_number="SEAL-0001",
                                    at=self.t(minutes=30))
        self.assertEqual(out["event_type"], EventType.TRANSFER_OUT.value)

    def test_temperature_excursion_auto_quarantines(self):
        sid = self.scan()["sample_id"]
        res = self.svc.record_temperature(OFFICER, sid, 12.5,
                                          recorded_at=self.t(hours=2))
        self.assertIsNotNone(res["quarantine_event"])
        self.assertEqual(res["quarantine_event"]["payload"]["anomaly_type"],
                         AnomalyType.TEMPERATURE_EXCURSION.value)
        sample = self.svc.get_sample(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(sample["status"], SampleStatus.QUARANTINED.value)

    def test_condemn_then_destroy_with_authorization(self):
        sid = self.scan()["sample_id"]
        self.svc.report_anomaly(OFFICER, sid, AnomalyType.CONTAINER_DAMAGED,
                                "样本瓶破裂", at=self.t(hours=2))
        self.svc.resolve_quarantine(
            COMPLIANCE, sid, QuarantineResolution.CONDEMN,
            authorization_ref="ADAMS-RULING-2026-200", at=self.t(hours=1))
        ev = self.svc.destroy_sample(
            COMPLIANCE, sid, authorization_ref="ADAMS-DESTRUCTION-2026-201",
            method="高温焚烧", at=self.t(minutes=30))
        self.assertEqual(ev["payload"]["authorization_ref"], "ADAMS-DESTRUCTION-2026-201")
        sample = self.svc.get_sample(sid, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(sample["status"], SampleStatus.DESTROYED.value)


class MaskingTest(CustodyTestCase):
    def test_identity_masked_by_role(self):
        sid = self.scan()["sample_id"]

        lab_view = self.svc.get_sample(sid, as_role=Role.LAB_TECHNICIAN)
        self.assertEqual(set(lab_view["athlete"].keys()), {"athlete_ref"})
        self.assertNotIn("张伟", json.dumps(lab_view, ensure_ascii=False))
        self.assertNotIn("110101199001011234", json.dumps(lab_view, ensure_ascii=False))

        courier_view = self.svc.get_sample(sid, as_role=Role.COURIER)
        self.assertEqual(courier_view["athlete"]["name"], "张***")
        self.assertTrue(courier_view["athlete"]["id_number"].startswith("ID-"))
        self.assertNotIn("110101199001011234",
                         json.dumps(courier_view, ensure_ascii=False))

        for role in (Role.COMPLIANCE_OFFICER, Role.SAMPLING_OFFICER):
            full = self.svc.get_sample(sid, as_role=role)
            self.assertEqual(full["athlete"]["name"], "张伟")
            self.assertEqual(full["athlete"]["id_number"], "110101199001011234")

    def test_masked_export_is_not_independently_verifiable(self):
        sid = self.deliver_to_lab()
        lab_export = self.svc.export_audit(sample_id=sid, as_role=Role.LAB_TECHNICIAN)
        self.assertIsNone(lab_export["verification"])
        blob = json.dumps(lab_export, ensure_ascii=False)
        self.assertNotIn("张伟", blob)
        self.assertNotIn("110101199001011234", blob)
        with self.assertRaises(ValidationError):
            self.svc.verify_export(lab_export)

        compliance_export = self.svc.export_audit(sample_id=sid,
                                                  as_role=Role.COMPLIANCE_OFFICER)
        self.assertTrue(self.svc.verify_export(compliance_export))

    def test_full_export_has_verified_linkage(self):
        self.deliver_to_lab()
        export = self.svc.export_audit(as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(export["verification"]["linkage"], "verified")
        self.assertTrue(self.svc.verify_export(export))


class LabWorkflowTest(CustodyTestCase):
    def test_split_requires_lab_and_custody(self):
        sid = self.deliver_to_lab()
        with self.assertRaises(PermissionDenied):
            self.svc.split_ab(OFFICER, sid, barcode_a="A-1", barcode_b="B-1",
                              seal_a="SA", seal_b="SB", at=self.t(minutes=50))
        split = self.svc.split_ab(LAB, sid, barcode_a="A-1", barcode_b="B-1",
                                  seal_a="SA", seal_b="SB", at=self.t(minutes=50))
        children = split["payload"]["children"]
        self.assertEqual({c["bottle"] for c in children}, {"A", "B"})
        # 父瓶为终态，不能再交接
        with self.assertRaises(InvalidState):
            self.svc.transfer_out(LAB, sid, COMPLIANCE, seal_number="SEAL-0001",
                                  at=self.t(minutes=40))
        # 不能重复拆分
        with self.assertRaises(InvalidState):
            self.svc.split_ab(LAB, sid, barcode_a="A-2", barcode_b="B-2",
                              seal_a="SA2", seal_b="SB2", at=self.t(minutes=40))

    def test_retest_requires_authorization(self):
        sid = self.deliver_to_lab()
        split = self.svc.split_ab(LAB, sid, barcode_a="A-1", barcode_b="B-1",
                                  seal_a="SA", seal_b="SB", at=self.t(minutes=50))
        child_a = split["payload"]["children"][0]["sample_id"]
        self.svc.record_result(LAB, child_a, "ADVERSE", lab_reference="LAB-RPT-9",
                               at=self.t(minutes=40))

        with self.assertRaises(ValidationError):
            self.svc.request_retest(LAB, child_a, authorization_ref="",
                                    reason="运动员申诉", at=self.t(minutes=30))
        with self.assertRaises(PermissionDenied):
            self.svc.request_retest(COURIER, child_a, authorization_ref="X",
                                    reason="越权角色", at=self.t(minutes=30))

        ev = self.svc.request_retest(LAB, child_a,
                                     authorization_ref="RMA-APPEAL-2026-31",
                                     reason="运动员申诉复检",
                                     at=self.t(minutes=30))
        self.assertEqual(ev["payload"]["authorization_ref"], "RMA-APPEAL-2026-31")
        sample = self.svc.get_sample(child_a, as_role=Role.COMPLIANCE_OFFICER)
        self.assertEqual(sample["status"], SampleStatus.RETEST_AUTHORIZED.value)
        # 复检授权后可以再次登记结果
        self.svc.record_result(LAB, child_a, "ADVERSE-CONFIRMED",
                               lab_reference="LAB-RPT-9B", at=self.t(minutes=20))

    def test_destroy_requires_compliance_and_authorization(self):
        sid = self.deliver_to_lab()
        with self.assertRaises(PermissionDenied):
            self.svc.destroy_sample(LAB, sid, authorization_ref="X",
                                    method="焚烧", at=self.t(minutes=30))
        with self.assertRaises(ValidationError):
            self.svc.destroy_sample(COMPLIANCE, sid, authorization_ref="",
                                    method="焚烧", at=self.t(minutes=30))
        self.svc.destroy_sample(COMPLIANCE, sid,
                                authorization_ref="ADAMS-DESTRUCTION-2026-300",
                                method="高温焚烧", at=self.t(minutes=30))
        with self.assertRaises(InvalidState):
            self.svc.transfer_out(LAB, sid, COMPLIANCE, seal_number="SEAL-0001",
                                  at=self.t(minutes=20))


class BatchHandoverTest(CustodyTestCase):
    def test_batch_handover_end_to_end(self):
        views = [self.scan(f"BC-B{i}", f"SEAL-B{i}", athlete_id=f"ATH-B{i}")
                 for i in range(3)]
        sids = [v["sample_id"] for v in views]
        outs = self.svc.batch_transfer_out(
            OFFICER,
            [{"sample_id": s, "seal_number": f"SEAL-B{i}"} for i, s in enumerate(sids)],
            COURIER, at=self.t(hours=2), idempotency_key="batch-out-1",
        )
        self.assertEqual(len(outs), 3)
        ins = self.svc.batch_transfer_in(
            COURIER,
            [{"sample_id": s, "dispatch_event_id": o["event_id"],
              "seal_number": f"SEAL-B{i}"} for i, (s, o) in enumerate(zip(sids, outs))],
            at=self.t(hours=1), idempotency_key="batch-in-1",
        )
        self.assertEqual(len(ins), 3)
        for s in sids:
            sample = self.svc.get_sample(s, as_role=Role.COMPLIANCE_OFFICER)
            self.assertEqual(sample["status"], SampleStatus.IN_CUSTODY.value)
            self.assertEqual(sample["current_custodian"]["actor_id"], COURIER)

    def test_batch_preflight_quarantines_only_bad_seal(self):
        good = self.scan("BC-G", "SEAL-G")["sample_id"]
        bad = self.scan("BC-BAD", "SEAL-REAL")["sample_id"]
        with self.assertRaises(SealMismatch):
            self.svc.batch_transfer_out(
                OFFICER,
                [{"sample_id": good, "seal_number": "SEAL-G"},
                 {"sample_id": bad, "seal_number": "SEAL-FORGED"}],
                COURIER, at=self.t(hours=2), idempotency_key="batch-out-2",
            )
        # 预检失败：好样本未被交出，坏样本已隔离
        self.assertEqual(self.svc.get_sample(good, as_role=Role.COMPLIANCE_OFFICER)["status"],
                         SampleStatus.SEALED.value)
        self.assertEqual(self.svc.get_sample(bad, as_role=Role.COMPLIANCE_OFFICER)["status"],
                         SampleStatus.QUARANTINED.value)


if __name__ == "__main__":
    unittest.main()
