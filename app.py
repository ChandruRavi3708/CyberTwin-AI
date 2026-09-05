"""CyberTwin AI: single Streamlit coordinator for all platform modules."""

from __future__ import annotations

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from modules.attack_forecasting import forecast_next_attack, get_attack_timeline
from modules.attack_graph import build_attack_graph, find_attack_paths, get_critical_assets, get_graph_summary
from modules.concept_drift import monitor_concept_drift
from modules.data_processing import preprocess_data
from modules.dataset_adapter import convert_cic_to_cybertwin, detect_dataset_schema, sample_large_dataset, validate_cybertwin_schema
from modules.defense_recommendation import rank_defense_recommendations
from modules.defense_simulation import check_attack_path, simulate_defense
from modules.evidence_chain import build_evidence_chain, get_evidence_summary, verify_evidence_chain
from modules.llm_explainer import answer_security_question, generate_security_explanation
from modules.mitre_mapping import map_to_mitre
from modules.network_digital_twin import create_digital_twin, get_twin_state
from modules.risk_scoring import calculate_risk
from modules.threat_detection import detect_anomalies, detect_known_threats
from modules.xai_engine import explain_event
from modules.zero_day_detection import detect_unknown_behaviour


st.set_page_config(page_title="CyberTwin AI", page_icon="🛡️", layout="wide")
st.markdown("""<style>.stApp {background:#07111f;color:#e6f1ff}.stMetric{background:#0d1b2a;padding:12px;border-radius:8px;border:1px solid #1c3b55}</style>""", unsafe_allow_html=True)


@st.cache_data
def load_pipeline() -> tuple[pd.DataFrame, nx.DiGraph, dict[str, object], list[dict[str, object]]]:
    raw = pd.read_csv("data/network_events.csv")
    data = calculate_risk(map_to_mitre(detect_unknown_behaviour(detect_anomalies(detect_known_threats(preprocess_data(raw))))))
    graph = build_attack_graph(data[data["known_threat"] | data["ai_risk_level"].isin(["High", "Critical"])])
    return data, graph, monitor_concept_drift(data), build_evidence_chain(data[data["ai_risk_level"] == "Critical"], critical_only=True)


df, attack_graph, drift_summary, evidence_chain = load_pipeline()
PAGES = ["SOC Overview", "Network Monitoring", "Threat Detection", "Attack Graph", "Attack Forecast", "Unknown Behaviour Detection", "Concept Drift Monitor", "Digital Twin", "What-If Defense Simulation", "AI Defense Recommendation", "XAI Investigation", "Security Copilot", "Evidence Integrity", "📂 Dataset Analysis"]
st.sidebar.title("🛡️ CyberTwin AI")
page = st.sidebar.radio("Navigation", PAGES, key="nav_page")
risk_filter = st.sidebar.multiselect("Risk level", sorted(df.risk_level.unique()), default=sorted(df.risk_level.unique()), key="nav_risk_filter")
event_filter = st.sidebar.multiselect("Event type", sorted(df.event_type.unique()), default=sorted(df.event_type.unique()), key="nav_event_filter")
filtered = df[df.risk_level.isin(risk_filter) & df.event_type.isin(event_filter)]
st.title("🛡️ CyberTwin AI")
st.caption("AI-Powered Predictive Cyber Defense & Network Digital Twin Platform")


def graph_plot(graph: nx.DiGraph, title: str) -> None:
    if not graph.nodes:
        st.info("No graph data is available."); return
    fig, ax = plt.subplots(figsize=(10, 6)); pos = nx.spring_layout(graph, seed=42)
    colors = ["#ef4444" if d.get("node_type") == "critical_asset" else "#f59e0b" if d.get("node_type") == "external_ip" else "#38bdf8" for _, d in graph.nodes(data=True)]
    nx.draw(graph, pos, with_labels=True, arrows=True, node_color=colors, node_size=900, font_size=7, ax=ax)
    ax.set_title(title); ax.axis("off"); st.pyplot(fig); plt.close(fig)


def run_cybertwin_pipeline(events: pd.DataFrame, train_on_benign_only: bool = False) -> tuple[pd.DataFrame, nx.DiGraph, dict[str, object]]:
    """Use the same CyberTwin modules for normalized uploaded flow records."""
    processed = preprocess_data(events)
    training_data = None
    if train_on_benign_only and "original_label" in processed:
        benign = processed[processed["original_label"].astype(str).str.strip().str.lower().isin({"benign", "normal"})]
        if len(benign) >= 2:
            training_data = benign
    detected = detect_anomalies(detect_known_threats(processed), training_data=training_data)
    results = calculate_risk(map_to_mitre(detect_unknown_behaviour(detected)))
    graph_events = results[results["ai_risk_level"].isin(["High", "Critical"])].nlargest(100, "risk_score")
    graph = build_attack_graph(graph_events)
    return results, graph, {"benign_training_rows": 0 if training_data is None else len(training_data)}


if page == "SOC Overview":
    cols = st.columns(4); cols[0].metric("Events", len(filtered)); cols[1].metric("High risk", int(filtered.risk_level.isin(["High", "Critical"]).sum())); cols[2].metric("Critical", int((filtered.risk_level == "Critical").sum())); cols[3].metric("Sources", filtered.source_ip.nunique())
    left, right = st.columns(2)
    with left: st.plotly_chart(px.bar(filtered.risk_level.value_counts().reset_index(), x="risk_level", y="count", title="Risk distribution"), width="stretch")
    with right: st.plotly_chart(px.line(filtered.groupby(pd.Grouper(key="timestamp", freq="5min")).size().reset_index(name="events"), x="timestamp", y="events", title="Activity timeline"), width="stretch")
    st.dataframe(filtered[filtered.risk_level.isin(["High", "Critical"])].sort_values("risk_score", ascending=False).head(20), width="stretch")

elif page == "Network Monitoring":
    st.plotly_chart(px.scatter(filtered, x="timestamp", y="data_transfer", size="packet_size", color="risk_level", hover_data=["source_ip", "destination_ip", "event_type"], title="Network telemetry"), width="stretch")
    st.dataframe(filtered, height=420, width="stretch")

elif page == "Threat Detection":
    cols = st.columns(4); cols[0].metric("Known threats", int(filtered.known_threat.sum())); cols[1].metric("AI anomalies", int(filtered.is_anomaly.sum())); cols[2].metric("Avg anomaly", round(filtered.anomaly_score.mean(), 2)); cols[3].metric("Avg risk", round(filtered.risk_score.mean(), 1))
    st.dataframe(filtered[filtered.known_threat | filtered.is_anomaly][["timestamp", "source_ip", "event_type", "threat_type", "anomaly_score", "risk_score", "mitre_id", "mitre_technique"]].sort_values("risk_score", ascending=False), width="stretch")

elif page == "Attack Graph":
    summary = get_graph_summary(attack_graph); cols = st.columns(4)
    for col, (label, value) in zip(cols, [("Nodes", summary["total_nodes"]), ("Edges", summary["total_connections"]), ("Suspicious", summary["suspicious_nodes"]), ("Critical assets", summary["critical_assets"])]): col.metric(label, value)
    graph_plot(attack_graph, "Observed threat relationships")
    for path in find_attack_paths(attack_graph): st.code(" → ".join(path))

elif page == "Attack Forecast":
    sources = sorted(df[df.known_threat].source_ip.unique().tolist())
    if sources:
        source = st.selectbox("Suspicious source", sources, key="forecast_source")
        forecast = forecast_next_attack(df, source, attack_graph)
        if forecast["prediction"]: st.success(f"{forecast['prediction']} — {forecast['confidence']}% confidence"); st.write(forecast["reason"]); st.dataframe(pd.DataFrame(get_attack_timeline(df, source)), width="stretch")
        else: st.info(forecast["status"])

elif page == "Unknown Behaviour Detection":
    novel = filtered[filtered.zero_day_alert]
    st.warning("This identifies unknown / novel suspicious behaviour; it does not claim real zero-day exploit detection.")
    st.metric("Novel behaviour alerts", len(novel)); st.dataframe(novel[["timestamp", "source_ip", "event_type", "unknown_behavior_score", "known_attack_match", "novelty_label"]], width="stretch")

elif page == "Concept Drift Monitor":
    cols = st.columns(3); cols[0].metric("Drift status", str(drift_summary["drift_level"])); cols[1].metric("Drift score", drift_summary["drift_score"]); cols[2].metric("Recent events", drift_summary["recent_events"])
    st.bar_chart(pd.Series(drift_summary["feature_drift"], name="drift"))

elif page == "Digital Twin":
    twin = create_digital_twin(attack_graph); state = get_twin_state(twin); cols = st.columns(4)
    for col, (label, value) in zip(cols, [("Nodes", state["nodes"]), ("Connections", state["connections"]), ("Average risk", state["average_risk"]), ("Active paths", state["active_attack_path_count"])]): col.metric(label, value)
    graph_plot(twin, "Safe digital twin")

elif page == "What-If Defense Simulation":
    twin = create_digital_twin(attack_graph); nodes, edges = list(twin.nodes), list(twin.edges)
    if nodes:
        action = st.selectbox("Defense action", ["Block IP", "Isolate Host", "Block Connection", "Protect Critical Asset"], key="sim_action")
        target = st.selectbox("Target asset", nodes, key="sim_target")
        edge = st.selectbox("Connection", edges or [(None, None)], key="sim_connection")
        attacker = st.selectbox("Attack source", nodes, key="sim_attacker"); critical = st.selectbox("Critical target", [n for n in nodes if n != attacker], key="sim_critical")
        if st.button("Run simulation", key="sim_run"):
            result = simulate_defense(twin, action, target=target, source=edge[0], destination=edge[1], attacker=attacker, critical_target=critical)
            cols = st.columns(4); cols[0].metric("Before risk", result["before_risk"]); cols[1].metric("After risk", result["after_risk"]); cols[2].metric("Reduction", f"{result['risk_reduction_percent']}%"); cols[3].metric("Path disrupted", "YES" if result["attack_path_disrupted"] else "NO")

elif page == "AI Defense Recommendation":
    recommendations = rank_defense_recommendations(create_digital_twin(attack_graph))
    st.dataframe(pd.DataFrame(recommendations)[["action", "target", "risk_reduction_percent", "path_reduction_percent", "attack_path_disrupted", "operational_cost", "defense_score"]], width="stretch")

elif page == "XAI Investigation":
    candidates = filtered.sort_values("risk_score", ascending=False)
    if not candidates.empty:
        index = st.selectbox("Event", candidates.index.tolist(), format_func=lambda i: f"{candidates.loc[i, 'source_ip']} — {candidates.loc[i, 'event_type']} ({candidates.loc[i, 'risk_score']})", key="xai_event")
        explanation = explain_event(candidates.loc[index]); st.subheader("Why was this flagged?"); st.write(" • ".join(explanation["why_flagged"])); st.dataframe(pd.DataFrame(explanation["top_contributing_factors"]), width="stretch"); st.write(explanation["recommended_investigation_steps"])

elif page == "Security Copilot":
    candidates = filtered.sort_values("risk_score", ascending=False)
    if not candidates.empty:
        index = st.selectbox("Event context", candidates.index.tolist(), key="copilot_event")
        question = st.selectbox("Ask the copilot", ["Why is this host dangerous?", "What should I investigate?", "What MITRE technique is this?", "What could happen next?", "What defense action is recommended?"], key="copilot_question")
        st.info(answer_security_question(question, candidates.loc[index], attack_graph)); st.caption(generate_security_explanation(candidates.loc[index], attack_graph))

elif page == "Evidence Integrity":
    evidence = get_evidence_summary(evidence_chain); cols = st.columns(3); cols[0].metric("Evidence records", evidence["evidence_records"]); cols[1].metric("Integrity", evidence["chain_integrity"]); cols[2].metric("Latest hash", str(evidence["latest_hash"])[:16] + "…")
    if verify_evidence_chain(evidence_chain): st.success("Evidence hash chain integrity verified.")
    else: st.error(evidence["reason"])
    st.dataframe(pd.DataFrame(evidence_chain)[["index", "timestamp", "previous_hash", "current_hash"]] if evidence_chain else pd.DataFrame(), width="stretch")

elif page == "📂 Dataset Analysis":
    st.header("📂 Dataset Analysis")
    st.caption("Upload a CIC-style or other network-flow CSV. Labels are optional and are used only after detection for prototype evaluation.")
    uploaded = st.file_uploader("Upload network traffic CSV", type=["csv"], key="dataset_upload_file")
    if uploaded is None:
        st.info("Upload a CSV to normalize it into CyberTwin events and run the existing AI pipeline.")
    else:
        file_id = f"{uploaded.name}:{uploaded.size}"
        if st.session_state.get("dataset_file_id") != file_id:
            try:
                st.session_state.dataset_raw_df = pd.read_csv(uploaded, low_memory=False)
                st.session_state.dataset_file_id = file_id
                for key in ("dataset_normalized_df", "dataset_results_df", "dataset_attack_graph", "dataset_forecast_results", "dataset_analysis_completed"):
                    st.session_state.pop(key, None)
            except (UnicodeDecodeError, pd.errors.ParserError, ValueError) as error:
                st.error(f"The CSV could not be read: {error}")
        raw = st.session_state.get("dataset_raw_df")
        if raw is not None:
            max_rows = st.selectbox("Maximum rows to analyze", [1_000, 5_000, 10_000, 25_000, 50_000], index=1, key="dataset_sample_size")
            sampling_method = st.selectbox("Sampling method", ["Random Sample", "First N Rows"], key="dataset_sampling_method")
            preview_rows = st.selectbox("Preview rows", [5, 10, 25], key="dataset_preview_rows")
            selection_id = f"{file_id}:{max_rows}:{sampling_method}"
            if st.session_state.get("dataset_selection_id") != selection_id:
                st.session_state.dataset_selection_id = selection_id
                for key in ("dataset_results_df", "dataset_attack_graph", "dataset_forecast_results", "dataset_analysis_completed"):
                    st.session_state.pop(key, None)
            selected = sample_large_dataset(raw, max_rows=max_rows, method=sampling_method)
            normalized, schema = convert_cic_to_cybertwin(selected)
            st.session_state.dataset_normalized_df = normalized
            st.subheader("1. Upload and dataset preview")
            cols = st.columns(4); cols[0].metric("Dataset", uploaded.name); cols[1].metric("Original rows", len(raw)); cols[2].metric("Selected rows", len(selected)); cols[3].metric("File size", f"{uploaded.size / 1_048_576:.2f} MB")
            st.dataframe(raw.head(preview_rows), width="stretch")
            st.subheader("2. Detected schema and data quality")
            schema_display = {source: target for target, source in schema["mapping"].items()}
            st.json({"column_mapping": schema_display, "columns_detected": schema["detected_columns"], "missing_important": schema["missing_important"], "fallbacks": schema["fallbacks"]})
            numeric = selected.select_dtypes(include=np.number)
            quality = {"missing_values": int(selected.isna().sum().sum()), "duplicate_rows": int(selected.duplicated().sum()), "infinite_values": int(np.isinf(numeric.to_numpy()).sum()) if not numeric.empty else 0, "numeric_columns": len(numeric.columns), "categorical_columns": len(selected.select_dtypes(exclude=np.number).columns)}
            st.dataframe(pd.DataFrame([quality]), width="stretch")
            if schema["missing_important"]:
                st.warning("Missing important fields: " + ", ".join(schema["missing_important"]) + ". Safe fallback values will be used where possible.")
            st.subheader("3. CyberTwin normalization")
            validation = validate_cybertwin_schema(normalized)
            if validation["is_valid"]:
                st.success("Normalized data is compatible with the existing CyberTwin event pipeline.")
                original_column, normalized_column = st.columns(2)
                with original_column: st.caption("Selected source-flow sample"); st.dataframe(selected.head(preview_rows), width="stretch")
                with normalized_column: st.caption("Normalized CyberTwin events"); st.dataframe(normalized.head(preview_rows), width="stretch")
            else:
                st.error("Normalization could not provide required fields: " + ", ".join(validation["missing_columns"]))
            has_benign = normalized["original_label"].astype(str).str.strip().str.lower().isin({"benign", "normal"}).any()
            train_benign = st.checkbox("Train Isolation Forest using BENIGN / NORMAL flows only", disabled=not has_benign, key="dataset_train_benign_only")
            if not has_benign:
                st.warning("No BENIGN / NORMAL labels were found; the existing unsupervised approach will be used.")
            if st.button("🚀 Run CyberTwin AI Analysis", key="dataset_run_analysis_btn", disabled=not validation["is_valid"]):
                with st.spinner("Running normalized flows through the CyberTwin pipeline..."):
                    try:
                        results, uploaded_graph, run_info = run_cybertwin_pipeline(normalized, train_benign)
                        st.session_state.dataset_results_df = results
                        st.session_state.dataset_attack_graph = uploaded_graph
                        st.session_state.dataset_forecast_results = run_info
                        st.session_state.dataset_analysis_completed = True
                    except (ValueError, TypeError) as error:
                        st.error(f"Analysis could not be completed: {error}")
            if st.session_state.get("dataset_analysis_completed"):
                results = st.session_state.dataset_results_df; uploaded_graph = st.session_state.dataset_attack_graph
                st.subheader("4. AI analysis results")
                cols = st.columns(6)
                metrics = [("Flows analyzed", len(results)), ("Anomalies", int(results.is_anomaly.sum())), ("High risk", int((results.ai_risk_level == "High").sum())), ("Critical", int((results.ai_risk_level == "Critical").sum())), ("Source hosts", results.source_ip.nunique()), ("Destination hosts", results.destination_ip.nunique())]
                for col, (label, value) in zip(cols, metrics): col.metric(label, value)
                left, right = st.columns(2)
                with left: st.plotly_chart(px.bar(results.ai_risk_level.value_counts().reset_index(), x="ai_risk_level", y="count", title="Risk level distribution"), width="stretch")
                with right: st.plotly_chart(px.histogram(results, x="anomaly_score", nbins=30, title="Anomaly score distribution"), width="stretch")
                host_risk = results.groupby("source_ip", as_index=False).risk_score.max().nlargest(10, "risk_score")
                st.plotly_chart(px.bar(host_risk, x="source_ip", y="risk_score", title="Top risky source hosts"), width="stretch")
                if results["original_label"].ne("Unknown").any(): st.plotly_chart(px.bar(results.original_label.value_counts().head(20).reset_index(), x="original_label", y="count", title="Traffic / attack label distribution"), width="stretch")
                mitre = results[results.mitre_id.ne("Unknown")].mitre_technique.value_counts().reset_index()
                if not mitre.empty: st.plotly_chart(px.bar(mitre, x="mitre_technique", y="count", title="MITRE ATT&CK mapping distribution (prototype contextual mapping)"), width="stretch")
                st.subheader("5. Attack graph, forecast, novelty, and drift")
                graph_plot(uploaded_graph, "Top high-risk uploaded flow relationships")
                sources = sorted(results[results.ai_risk_level.isin(["High", "Critical"])].source_ip.unique())
                if sources:
                    source = st.selectbox("Forecast source", sources, key="dataset_forecast_source")
                    forecast = forecast_next_attack(results, source, uploaded_graph)
                    st.info("Predicted plausible next attack stage: " + (forecast["prediction"] or forecast["status"]))
                    if forecast["prediction"]: st.caption(f"{forecast['confidence']}% confidence — {forecast['reason']}")
                novel = results[results.zero_day_alert]
                st.warning(f"Unknown / Novel Suspicious Behaviour alerts: {len(novel)}. This is not a guaranteed zero-day detection.")
                st.dataframe(novel[["source_ip", "destination_ip", "unknown_behavior_score", "known_attack_match", "novelty_label"]], width="stretch")
                drift = monitor_concept_drift(results, recent_fraction=0.5)
                st.metric("Dataset segment drift", f"{drift['drift_level']} ({drift['drift_score']})")
                if results["original_label"].ne("Unknown").any():
                    st.subheader("6. Prototype Evaluation on Uploaded Dataset")
                    truth = ~results.original_label.astype(str).str.strip().str.lower().isin({"benign", "normal", "unknown", ""})
                    prediction = results.is_anomaly.astype(bool)
                    cols = st.columns(3); cols[0].metric("Precision", round(precision_score(truth, prediction, zero_division=0), 3)); cols[1].metric("Recall", round(recall_score(truth, prediction, zero_division=0), 3)); cols[2].metric("F1", round(f1_score(truth, prediction, zero_division=0), 3))
                    matrix = confusion_matrix(truth, prediction, labels=[False, True])
                    st.dataframe(pd.DataFrame(matrix, index=["Actual benign", "Actual attack"], columns=["Predicted normal", "Predicted anomaly"]), width="stretch")
