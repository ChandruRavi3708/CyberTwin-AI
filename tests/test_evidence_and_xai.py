"""Tests for tamper-evident evidence and offline analyst explanation modules."""

import copy
import unittest

from modules.evidence_chain import build_evidence_chain, verify_evidence_chain, verify_evidence_chain_details
from modules.event_generator import generate_network_events
from modules.llm_explainer import generate_security_explanation
from modules.xai_engine import explain_event


class EvidenceAndXaiTests(unittest.TestCase):
    def setUp(self):
        self.events = generate_network_events(event_count=20, seed=3)

    def test_modified_evidence_is_detected(self):
        chain = build_evidence_chain(self.events.head(3))
        altered = copy.deepcopy(chain)
        altered[1]["event_data"]["source_ip"] = "203.0.113.1"
        self.assertTrue(verify_evidence_chain(chain))
        self.assertFalse(verify_evidence_chain(altered))
        self.assertEqual(verify_evidence_chain_details(altered)["invalid_index"], 1)

    def test_local_explanation_requires_no_provider(self):
        explanation = explain_event(self.events.iloc[0])
        narrative = generate_security_explanation(self.events.iloc[0])
        self.assertIn("why_flagged", explanation)
        self.assertIn("Recommended analyst action", narrative)


if __name__ == "__main__":
    unittest.main()
