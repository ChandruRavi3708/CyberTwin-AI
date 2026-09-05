"""Tests for explainable risk calculation and novelty/drift monitoring."""

import unittest

import pandas as pd

from modules.concept_drift import calculate_concept_drift
from modules.dataset_adapter import convert_cic_to_cybertwin
from modules.data_processing import preprocess_data
from modules.event_generator import generate_network_events
from modules.mitre_mapping import map_to_mitre
from modules.risk_scoring import calculate_risk
from modules.threat_detection import detect_anomalies, detect_known_threats
from modules.zero_day_detection import detect_unknown_behaviour


def processed_events():
    events = preprocess_data(generate_network_events(event_count=100, seed=7))
    return calculate_risk(map_to_mitre(detect_anomalies(detect_known_threats(events))))


class RiskEngineTests(unittest.TestCase):
    def test_scores_and_explanations_are_bounded(self):
        result = processed_events()
        self.assertTrue(result["risk_score"].between(0, 100).all())
        self.assertTrue(set(result["ai_risk_level"]).issubset({"Low", "Medium", "High", "Critical"}))
        self.assertTrue(result["risk_factor_contributions"].map(lambda item: isinstance(item, dict)).all())

    def test_novel_behaviour_does_not_mislabel_known_attack(self):
        result = detect_unknown_behaviour(processed_events())
        known = result[result["known_threat"]]
        self.assertTrue((known["known_attack_match"] == 1.0).all())
        self.assertTrue(result["unknown_behavior_score"].between(0, 1).all())

    def test_large_distribution_change_is_high_drift(self):
        historical = pd.DataFrame({"failed_logins": [0] * 30, "connections": [1] * 30, "data_transfer": [100] * 30, "anomaly_score": [0.01] * 30})
        recent = pd.DataFrame({"failed_logins": [20] * 30, "connections": [80] * 30, "data_transfer": [100_000] * 30, "anomaly_score": [0.99] * 30})
        self.assertEqual(calculate_concept_drift(historical, recent)["drift_level"], "HIGH DRIFT")

    def test_adapter_output_can_use_benign_only_training(self):
        raw = generate_network_events(event_count=20, seed=8).rename(columns={"source_ip": "Source IP", "destination_ip": "Destination IP", "port": "Destination Port"})
        raw["Label"] = ["BENIGN"] * 10 + ["Attack"] * 10
        normalized, _ = convert_cic_to_cybertwin(raw)
        benign = preprocess_data(normalized[normalized["original_label"] == "BENIGN"])
        result = detect_anomalies(detect_known_threats(preprocess_data(normalized)), training_data=benign)
        self.assertEqual(len(result), len(normalized))


if __name__ == "__main__":
    unittest.main()
