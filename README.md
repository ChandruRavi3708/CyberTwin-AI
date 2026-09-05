# CyberTwin AI

CyberTwin AI is an offline, Streamlit-based predictive cyber-defense prototype for SIH. Phase 1 supplies deterministic synthetic telemetry and reusable data processing; existing modules provide the in-progress detection, risk, graph, forecast, and digital-twin layers.

## Install and run

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python generate_data.py
streamlit run app.py
```

## Phase 1 data pipeline

`modules.event_generator.generate_network_events()` creates reproducible baseline activity plus ordered attack chains: port scan, failed-login burst, credential abuse, lateral movement, privilege escalation, and high-volume data transfer. It writes `data/network_events.csv` through `save_network_events()`.

`modules.data_processing.preprocess_data()` validates and cleans data, adds time and model-friendly features, and preserves the legacy `bytes` column used by current dashboard modules.

## Phase 2 intelligence pipeline

`modules.threat_detection` combines transparent known-threat rules with a deterministic Isolation Forest. Its `anomaly_score` is normalised from 0 to 1. `modules.mitre_mapping` uses a local, replaceable MITRE ATT&CK configuration, while `modules.risk_scoring` produces an explainable 0--100 score, risk band, and per-factor contribution dictionary for every event.

## Phase 3 graph and forecasting

`modules.attack_graph` constructs a directed NetworkX graph from recognised threats and high-risk events. It supplies high-risk-node, neighbour, attack-path, and critical-path queries. `modules.attack_forecasting` predicts the next ATT&CK stage using the latest attack sequence, risk, and observed graph reachability, with an evidence-based confidence and reason.

## Phase 4 novelty and drift monitoring

`modules.zero_day_detection` identifies **Unknown / Novel Suspicious Behaviour** only when anomalous telemetry has little match to known rules; it does not claim to detect real zero-day exploits. `modules.concept_drift` compares historical and recent distributions for failed logins, connections, transfer volume, and anomaly score, returning a score plus NO/LOW/MODERATE/HIGH DRIFT status.

## Phase 5 digital-twin defense simulation

`modules.network_digital_twin` creates a deep-copied graph for safe what-if analysis. `modules.defense_simulation` models IP blocking, host isolation, connection blocking, and critical-asset protection with before/after risk and attack-path impact. `modules.defense_recommendation` ranks these controls using risk reduction, path disruption, and an operational-cost penalty.

## Phase 6 explainable investigation and copilot

`modules.xai_engine` turns risk-factor contributions into structured reasons, factor rankings, MITRE context, and investigation steps. `modules.llm_explainer` provides a fully local template security copilot and a safe provider interface for an optional future LLM integration; no API key is required or stored.

## Phase 7 tamper-evident evidence

`modules.evidence_chain` creates SHA-256 linked records containing event data, timestamp, previous hash, and current/event hash. It supports loading, saving, verification, and dashboard-ready integrity summaries. The application constructs an in-memory chain for Critical events; [data/evidence_chain.json](data/evidence_chain.json) is the persisted-chain starting point for the later dashboard workflow.

## Phase 8 dashboard integration

The single `app.py` coordinator integrates every completed module into 13 SOC views: SOC Overview, Network Monitoring, Threat Detection, Attack Graph, Attack Forecast, Unknown Behaviour Detection, Concept Drift Monitor, Digital Twin, What-If Defense Simulation, AI Defense Recommendation, XAI Investigation, Security Copilot, and Evidence Integrity. All interactive Streamlit controls have explicit globally unique keys.

## Testing

Run the full offline test suite with Python's built-in test runner:

```powershell
python -m unittest discover -s tests -v
```

The tests cover synthetic data and detection, risk and drift, attack graphs and defense simulations, evidence tampering, and the offline explanation fallback.

## Dataset analysis

The **📂 Dataset Analysis** page supports CIC-style intrusion-detection CSVs, general network-flow CSVs, and the included synthetic data. Its workflow is: **Upload CSV → Normalize Dataset → AI Analysis → Risk Scoring → MITRE Mapping → Attack Graph → Forecasting**.

The adapter detects common CIC columns such as Source IP, Destination IP, Destination Port, Protocol, Timestamp, Label, flow packet/byte features, and average packet size. It cleans malformed numeric values, safely samples large datasets, and converts flows to the CyberTwin event schema before passing them into the existing pipeline.

The dashboard accepts CSV uploads up to **10 GB** through the project Streamlit configuration (instead of Streamlit's 200 MB default). Analysis still uses the selected row sample cap to keep ML and graph operations responsive on a hackathon laptop.

Dataset labels are optional. When available, they are retained for post-analysis prototype evaluation only; they are not anomaly-model features. The page can optionally fit the Isolation Forest using BENIGN/NORMAL flows only, then evaluate the selected mixed flows.

To demo with a CIC CSV, open **📂 Dataset Analysis**, upload the CSV, select a capped sample size, review the schema/normalization previews, and select **Run CyberTwin AI Analysis**.

## Demo flow

Generate the dataset, open the SOC overview, then select a high-risk source in the attack forecast view. The final events form an ordered attacker-to-database scenario suitable for demonstrating the later phases as they are completed.
