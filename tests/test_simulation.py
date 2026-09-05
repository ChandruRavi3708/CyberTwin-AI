"""Tests for attack graph, forecasting, twin simulation, and recommendations."""

import unittest

from modules.attack_forecasting import forecast_next_attack
from modules.attack_graph import build_attack_graph, get_critical_assets
from modules.data_processing import preprocess_data
from modules.defense_recommendation import rank_defense_recommendations
from modules.defense_simulation import simulate_defense
from modules.event_generator import generate_network_events
from modules.mitre_mapping import map_to_mitre
from modules.network_digital_twin import create_digital_twin, reset_twin
from modules.risk_scoring import calculate_risk
from modules.threat_detection import detect_anomalies, detect_known_threats


def graph_fixture():
    events = preprocess_data(generate_network_events(event_count=120, seed=11))
    data = calculate_risk(map_to_mitre(detect_anomalies(detect_known_threats(events))))
    return data, build_attack_graph(data[data["known_threat"] | data["ai_risk_level"].isin(["High", "Critical"])])


class SimulationTests(unittest.TestCase):
    def setUp(self):
        self.data, self.graph = graph_fixture()
        self.twin = create_digital_twin(self.graph)
        self.attacker = next(node for node, value in self.twin.nodes(data=True) if value["node_type"] == "external_ip")
        self.asset = get_critical_assets(self.twin)[0]

    def test_block_ip_preserves_original_and_disrupts_selected_path(self):
        result = simulate_defense(self.twin, "Block IP", target=self.attacker, attacker=self.attacker, critical_target=self.asset)
        self.assertTrue(self.graph.has_node(self.attacker))
        self.assertFalse(result["graph"].has_node(self.attacker))
        self.assertTrue(result["attack_path_before"])
        self.assertFalse(result["attack_path_after"])

    def test_forecast_and_recommendations_are_available(self):
        forecast = forecast_next_attack(self.data, self.attacker, self.graph)
        self.assertIsNotNone(forecast["prediction"])
        recommendations = rank_defense_recommendations(self.twin)
        self.assertTrue(recommendations)
        self.assertGreaterEqual(recommendations[0]["defense_score"], recommendations[-1]["defense_score"])

    def test_twin_can_reset_to_baseline(self):
        self.twin.remove_node(self.attacker)
        self.assertTrue(reset_twin(self.twin).has_node(self.attacker))


if __name__ == "__main__":
    unittest.main()
