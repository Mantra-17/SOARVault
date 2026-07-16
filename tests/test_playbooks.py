import unittest
from playbooks.engine import PlaybookEngine, PlaybookResult
from playbooks.brute_force import BruteForcePlaybook
from playbooks.malware import MalwarePlaybook
from playbooks.mock_edr import MockEDR
from playbooks.actions import ActionResult

class TestPlaybooks(unittest.TestCase):
    """
    Unit test suite for SOAR playbook execution and risk score scenarios (Day 7).
    """

    def setUp(self):
        self.engine = PlaybookEngine()
        self.brute_force = BruteForcePlaybook()
        self.malware = MalwarePlaybook()
        self.edr = MockEDR()

    def test_brute_force_high_risk_triggers_block_ip(self):
        """Test: score 90 (>80) triggers block_ip and send_notification."""
        alert = {"type": "brute_force", "source_ip": "192.168.1.100"}
        result = self.brute_force.execute(alert, risk_score=90.0)
        
        self.assertIsInstance(result, PlaybookResult)
        self.assertEqual(result.status, "success")
        self.assertTrue(result.rollback_available)
        
        actions = [a.action for a in result.actions_taken]
        self.assertIn("block_ip", actions)
        self.assertIn("send_notification", actions)
        
        # Verify block_ip action details
        block_action = next(a for a in result.actions_taken if a.action == "block_ip")
        self.assertEqual(block_action.target, "192.168.1.100")
        self.assertEqual(block_action.status, "success")

    def test_brute_force_medium_risk_needs_approval(self):
        """Test: score 65 (50-80) sends notification only for approval."""
        alert = {"type": "brute_force", "source_ip": "192.168.1.101"}
        result = self.brute_force.execute(alert, risk_score=65.0)
        
        actions = [a.action for a in result.actions_taken]
        self.assertIn("send_notification", actions)
        self.assertNotIn("block_ip", actions)

    def test_brute_force_low_risk_only_logs(self):
        """Test: score 30 (<50) only logs, taking no response actions."""
        alert = {"type": "brute_force", "source_ip": "192.168.1.102"}
        result = self.brute_force.execute(alert, risk_score=30.0)
        
        actions = [a.action for a in result.actions_taken]
        self.assertIn("log", actions)
        self.assertNotIn("block_ip", actions)
        self.assertNotIn("send_notification", actions)
        self.assertFalse(result.rollback_available)

    def test_malware_high_risk_triggers_isolate_and_block(self):
        """Test: score 85 (>80) triggers isolate_host, block_ip, and notification."""
        alert = {"type": "malware", "host_id": "HOST-001", "source_ip": "10.10.10.50"}
        result = self.malware.execute(alert, risk_score=85.0)
        
        actions = [a.action for a in result.actions_taken]
        self.assertIn("isolate_host", actions)
        self.assertIn("block_ip", actions)
        self.assertIn("send_notification", actions)
        
        isolate_action = next(a for a in result.actions_taken if a.action == "isolate_host")
        self.assertEqual(isolate_action.target, "HOST-001")
        self.assertEqual(isolate_action.status, "success")

    def test_malware_medium_risk_flags_for_approval(self):
        """Test: score 60 (50-80) sends notification and flags for senior analyst approval."""
        alert = {"type": "malware", "host_id": "HOST-002", "source_ip": "10.10.10.51"}
        result = self.malware.execute(alert, risk_score=60.0)
        
        actions = [a.action for a in result.actions_taken]
        self.assertIn("send_notification", actions)
        self.assertIn("flag_for_approval", actions)
        self.assertNotIn("isolate_host", actions)
        self.assertNotIn("block_ip", actions)

    def test_malware_low_risk_only_logs(self):
        """Test: score 30 (<50) only logs for malware containment."""
        alert = {"type": "malware", "host_id": "HOST-003", "source_ip": "10.10.10.52"}
        result = self.malware.execute(alert, risk_score=30.0)
        
        actions = [a.action for a in result.actions_taken]
        self.assertIn("log", actions)
        self.assertNotIn("isolate_host", actions)
        self.assertNotIn("block_ip", actions)

    def test_mock_edr_responses(self):
        """Test: mock EDR returns correct responses for isolate, scan, and get_status."""
        # Initial status check
        status_before = self.edr.get_status("HOST-500")
        self.assertEqual(status_before["host_id"], "HOST-500")
        self.assertEqual(status_before["status"], "connected")

        # Initiate scan
        scan_res = self.edr.scan("HOST-500")
        self.assertEqual(scan_res["host_id"], "HOST-500")
        self.assertEqual(scan_res["scan_status"], "started")

        # Isolate host
        isolate_res = self.edr.isolate("HOST-500")
        self.assertEqual(isolate_res["host_id"], "HOST-500")
        self.assertEqual(isolate_res["status"], "isolated")

        # Status check after isolation
        status_after = self.edr.get_status("HOST-500")
        self.assertEqual(status_after["status"], "isolated")

    def test_playbook_engine_routing_and_execution(self):
        """Test: PlaybookEngine routes correctly to BruteForce and Malware playbooks."""
        alert_bf = {"type": "brute_force", "source_ip": "172.16.0.5"}
        res_bf = self.engine.execute(alert_bf, risk_score=95.0)
        self.assertEqual(res_bf.status, "success")
        self.assertTrue(any(a.action == "block_ip" for a in res_bf.actions_taken))

        alert_mw = {"type": "malware", "host_id": "HOST-999", "source_ip": "172.16.0.6"}
        res_mw = self.engine.execute(alert_mw, risk_score=95.0)
        self.assertEqual(res_mw.status, "success")
        self.assertTrue(any(a.action == "isolate_host" for a in res_mw.actions_taken))

if __name__ == "__main__":
    unittest.main()
