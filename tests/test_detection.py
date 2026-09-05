"""Tests for Phase 1 data generation and Phase 2 detection/MITRE modules."""

import unittest

from modules.data_processing import preprocess_data
from modules.dataset_adapter import convert_cic_to_cybertwin, sample_large_dataset, validate_cybertwin_schema
from modules.event_generator import generate_network_events
from modules.mitre_mapping import map_to_mitre
from modules.threat_detection import detect_anomalies, detect_known_threats


class DetectionPipelineTests(unittest.TestCase):
    def setUp(self):
        self.events = preprocess_data(generate_network_events(event_count=80, seed=42))
        self.detected = detect_anomalies(detect_known_threats(self.events))

    def test_generator_provides_required_schema_and_attack_sequence(self):
        required = {"timestamp", "source_ip", "destination_ip", "connections", "data_transfer", "packet_size", "request_frequency", "scenario_id"}
        self.assertTrue(required.issubset(self.events.columns))
        self.assertIn("attack-01", set(self.events["scenario_id"]))
        self.assertIn("Credential Abuse", set(self.events["event_type"]))

    def test_anomaly_scores_are_readable_and_known_threats_are_flagged(self):
        self.assertTrue(self.detected["anomaly_score"].between(0, 1).all())
        self.assertTrue(self.detected["known_threat"].any())
        self.assertTrue(self.detected["is_anomaly"].any())

    def test_mitre_mapping_covers_core_attack_techniques(self):
        mapped = map_to_mitre(self.detected)
        self.assertTrue({"T1046", "T1110", "T1078", "T1021", "T1041"}.issubset(set(mapped["mitre_id"])))

    def test_cic_style_adapter_handles_aliases_and_malformed_values(self):
        cic = self.events.head(4).rename(columns={"source_ip": " Source IP ", "destination_ip": "Destination IP", "port": " Destination Port", "timestamp": "Timestamp", "data_transfer": "Flow Bytes/s", "packet_size": "Average Packet Size", "request_frequency": "Flow Packets/s"})
        cic["Label"] = ["BENIGN", "PortScan", "BENIGN", "DDoS"]
        cic["Flow Bytes/s"] = cic["Flow Bytes/s"].astype(float)
        cic.loc[cic.index[0], "Flow Bytes/s"] = float("inf")
        normalized, schema = convert_cic_to_cybertwin(cic)
        self.assertTrue(validate_cybertwin_schema(normalized)["is_valid"])
        self.assertTrue(schema["has_labels"])
        self.assertEqual(normalized.loc[normalized.index[0], "data_transfer"], 0)
        self.assertEqual(len(sample_large_dataset(cic, max_rows=2)), 2)

    def test_adapter_handles_no_label_and_missing_ips(self):
        flow_only = self.events[["port", "protocol", "connections", "data_transfer", "packet_size", "request_frequency"]].copy()
        normalized, schema = convert_cic_to_cybertwin(flow_only)
        self.assertFalse(schema["has_labels"])
        self.assertTrue((normalized["source_ip"] == "Unknown").all())
        self.assertTrue((normalized["original_label"] == "Unknown").all())


if __name__ == "__main__":
    unittest.main()
