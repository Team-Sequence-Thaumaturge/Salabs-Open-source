import sys, os, time, shutil, unittest, json
sys.path.insert(0, r"C:\stella.os\Quanxs\sair")
sys.path.insert(0, r"C:\stella.os\Quanxs\sair\SAPQ")

from sapq_arbiter import SAPQArbiter

class TestSAPQArbiter(unittest.TestCase):
    def setUp(self):
        if os.path.exists(".sapq_logs"):
            try:
                shutil.rmtree(".sapq_logs")
            except Exception:
                pass

    def test_generate_interrogation_dossier(self):
        arbiter = SAPQArbiter(session_id=f"test_dossier_{int(time.time()*1000)}")
        baseline_issues = [
            {"role_signature": "READS_STATE:True|WRITES_DOM:True", "original_functions": ["applyTheme"]}
        ]
        generic_issues = [
            {"issue": "TORSION_CROSSING: ref before def"}
        ]

        result_json = arbiter.generate_interrogation_dossier("target.js", baseline_issues, generic_issues)
        self.assertIsNotNone(result_json)

        dossier = json.loads(result_json)
        self.assertEqual(dossier["type"], "SAPQ_INTERROGATION")
        self.assertEqual(len(dossier["topological_holes"]), 2)
        self.assertEqual(dossier["topological_holes"][0]["missing_role"], "READS_STATE:True|WRITES_DOM:True")
        self.assertEqual(dossier["topological_holes"][1]["issue_type"], "TORSION_CROSSING")

    def test_oscillation_circuit_breaker(self):
        arbiter = SAPQArbiter(max_retries=3, session_id=f"test_osc_{int(time.time()*1000)}")

        arbiter.log_patch_attempt(score=50, issues_count=2)
        arbiter.log_patch_attempt(score=50, issues_count=2)
        self.assertFalse(arbiter.check_oscillation())

        arbiter.log_patch_attempt(score=50, issues_count=2)
        self.assertTrue(arbiter.check_oscillation())

        # Once circuit is broken, the dossier should yield RULE_CONFLICT_PAUSE
        result_json = arbiter.generate_interrogation_dossier("target.js", [{"role": "dummy"}])
        dossier = json.loads(result_json)
        self.assertEqual(dossier["type"], "RULE_CONFLICT_PAUSE")

if __name__ == '__main__':
    unittest.main()
