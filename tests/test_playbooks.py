import unittest
from playbooks.engine import PlaybookEngine
from playbooks.report import get_execution_report

class TestPlaybooks(unittest.TestCase):
    def setUp(self):
        self.engine = PlaybookEngine()

    def test_brute_force_high_risk(self):
        alert = {"type": "brute_force", "source_ip": "192.168.1.1"}
        result = self.engine.execute(alert, risk_score=90, case_id="case-1")
        self.assertEqual(result.status, "success")
        self.assertEqual(len(result.actions_taken), 2)
        self.assertEqual(result.actions_taken[0].action, "block_ip")
        
    def test_brute_force_low_risk(self):
        alert = {"type": "brute_force", "source_ip": "192.168.1.1"}
        result = self.engine.execute(alert, risk_score=30, case_id="case-2")
        self.assertEqual(result.status, "success")
        self.assertEqual(len(result.actions_taken), 1)
        self.assertEqual(result.actions_taken[0].action, "send_notification")
        self.assertEqual(result.actions_taken[0].target, "INFO")
        
    def test_malware_high_risk(self):
        alert = {"type": "malware", "host_id": "host-1", "source_ip": "10.0.0.1"}
        result = self.engine.execute(alert, risk_score=85, case_id="case-3")
        self.assertEqual(result.status, "success")
        self.assertEqual(len(result.actions_taken), 3)
        self.assertEqual(result.actions_taken[0].action, "isolate_host")
        
    def test_ddos_high_risk(self):
        alert = {"type": "ddos", "source_ip": "192.168.1.5"}
        result = self.engine.execute(alert, risk_score=75, case_id="case-4")
        self.assertEqual(len(result.actions_taken), 3)
        self.assertEqual(result.actions_taken[1].action, "rate_limit")
        
    def test_data_exfil_high_risk(self):
        alert = {"type": "data_exfil", "host_id": "server-1"}
        result = self.engine.execute(alert, risk_score=80, case_id="case-5")
        self.assertEqual(len(result.actions_taken), 3)
        self.assertEqual(result.actions_taken[1].action, "block_outbound")
        
    def test_insider_threat_high_risk(self):
        alert = {"type": "insider_threat", "user_id": "jdoe", "hour_of_day": 23, "unusual_access": True}
        result = self.engine.execute(alert, risk_score=90, case_id="case-6")
        self.assertEqual(len(result.actions_taken), 2)
        self.assertEqual(result.actions_taken[0].action, "disable_account")

    def test_unknown_alert_type(self):
        alert = {"type": "unknown_type"}
        result = self.engine.execute(alert, risk_score=100, case_id="case-7")
        self.assertEqual(result.status, "failed - unknown alert type")

    def test_rollback(self):
        alert = {"type": "brute_force", "source_ip": "192.168.1.1"}
        self.engine.execute(alert, risk_score=90, case_id="case-8")
        self.assertTrue(self.engine.undo_actions("case-8"))
        result = self.engine.case_history["case-8"]
        self.assertFalse(result.rollback_available)
        self.assertEqual(result.actions_taken[0].status, "rolled_back")

    def test_auto_rollback(self):
        alert = {"type": "brute_force", "source_ip": "192.168.1.1"}
        self.engine.execute(alert, risk_score=90, case_id="case-9")
        self.assertTrue(self.engine.check_auto_rollback("case-9", current_risk_score=40, hours_elapsed=1.5))
        
    def test_dry_run(self):
        alert = {"type": "brute_force", "source_ip": "192.168.1.1"}
        result = self.engine.execute(alert, risk_score=90, case_id="case-10", dry_run=True)
        self.assertEqual(result.actions_taken[0].status, "dry_run_success")
        
    def test_execution_report(self):
        alert = {"type": "brute_force", "source_ip": "192.168.1.1"}
        self.engine.execute(alert, risk_score=90, case_id="case-11")
        report = get_execution_report(self.engine, "case-11")
        self.assertEqual(report["case_id"], "case-11")
        self.assertEqual(report["status"], "success")
        self.assertEqual(len(report["actions_taken"]), 2)
        
    def test_rollback_invalid_case(self):
        self.assertFalse(self.engine.undo_actions("invalid-case"))

if __name__ == '__main__':
    unittest.main()
