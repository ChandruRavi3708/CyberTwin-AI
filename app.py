import streamlit as st
import pandas as pd
import plotly.express as px
from modules.data_processing import preprocess_data

from modules.threat_detection import (
    detect_anomalies,
    detect_known_threats
)

from modules.risk_scoring import calculate_risk

from modules.mitre_mapping import map_to_mitre

from modules.attack_graph import (
    build_attack_graph,
    get_suspicious_nodes,
    get_critical_assets,
    find_attack_paths,
    get_graph_summary
)

from modules.attack_forecasting import (
    forecast_next_attack,
    get_attack_timeline
)

# -------------------------------------------------
# PAGE CONFIG
# -------------------------------------------------

st.set_page_config(
    page_title="CyberTwin AI",
    page_icon="🛡️",
    layout="wide"
)


# -------------------------------------------------
# LOAD DATA
# -------------------------------------------------

@st.cache_data
def load_data():

    df = pd.read_csv(
        "data/network_events.csv"
    )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"]
    )

    return df


df = load_data()

# -----------------------------------
# AI PROCESSING PIPELINE
# -----------------------------------

df = preprocess_data(df)

df = detect_known_threats(df)

df = detect_anomalies(df)

df = calculate_risk(df)

df = map_to_mitre(df)

# -----------------------------------
# BUILD DYNAMIC ATTACK GRAPH
# -----------------------------------

# -----------------------------------
# BUILD GRAPH FROM HIGH-RISK EVENTS
# -----------------------------------

graph_data = df[
    df["ai_risk_level"].isin(
        ["High", "Critical"]
    )
]

attack_graph = build_attack_graph(
    graph_data
)

# -------------------------------------------------
# SIDEBAR
# -------------------------------------------------

st.sidebar.title("🛡️ CyberTwin AI")

st.sidebar.caption(
    "Predictive Cyber Defense Platform"
)

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 SOC Overview",
        "📡 Network Monitoring",
        "🚨 Threat Detection",
        "🕸️ Attack Graph",
        "🔮 Attack Forecast"
    ]
)

st.sidebar.divider()

st.sidebar.subheader("Filters")

risk_filter = st.sidebar.multiselect(
    "Risk Level",
    options=sorted(df["risk_level"].unique()),
    default=sorted(df["risk_level"].unique())
)

event_filter = st.sidebar.multiselect(
    "Event Type",
    options=sorted(df["event_type"].unique()),
    default=sorted(df["event_type"].unique())
)


# -------------------------------------------------
# APPLY FILTERS
# -------------------------------------------------

filtered_df = df[
    df["risk_level"].isin(risk_filter)
    &
    df["event_type"].isin(event_filter)
]


# -------------------------------------------------
# HEADER
# -------------------------------------------------

st.title("🛡️ CyberTwin AI")

st.caption(
    "AI-Powered Threat Detection • Attack Forecasting • Digital Twin Defense"
)

st.divider()


# =================================================
# SOC OVERVIEW
# =================================================

if page == "🏠 SOC Overview":

    st.header("Security Operations Center")

    # Metrics

    total_events = len(filtered_df)

    high_risk = len(
        filtered_df[
            filtered_df["risk_level"]
            .isin(["High", "Critical"])
        ]
    )

    critical_events = len(
        filtered_df[
            filtered_df["risk_level"]
            == "Critical"
        ]
    )

    suspicious_sources = filtered_df[
        filtered_df["risk_level"]
        .isin(["High", "Critical"])
    ]["source_ip"].nunique()


    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Events",
        total_events
    )

    col2.metric(
        "High Risk",
        high_risk
    )

    col3.metric(
        "Critical",
        critical_events
    )

    col4.metric(
        "Suspicious Sources",
        suspicious_sources
    )


    st.divider()


    # Two column charts

    col1, col2 = st.columns(2)


    with col1:

        risk_counts = (
            filtered_df["risk_level"]
            .value_counts()
            .reset_index()
        )

        risk_counts.columns = [
            "Risk Level",
            "Count"
        ]

        fig = px.bar(
            risk_counts,
            x="Risk Level",
            y="Count",
            title="Risk Distribution"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


    with col2:

        event_counts = (
            filtered_df["event_type"]
            .value_counts()
            .reset_index()
        )

        event_counts.columns = [
            "Event Type",
            "Count"
        ]

        fig = px.pie(
            event_counts,
            names="Event Type",
            values="Count",
            title="Network Event Distribution"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


    # Traffic over time

    st.subheader("Network Activity Over Time")

    timeline = (
        filtered_df
        .groupby(
            pd.Grouper(
                key="timestamp",
                freq="5min"
            )
        )
        .size()
        .reset_index(name="Event Count")
    )

    fig = px.line(
        timeline,
        x="timestamp",
        y="Event Count",
        title="Network Event Timeline"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


    st.divider()


    # Critical alerts

    st.subheader("🚨 Recent High-Risk Alerts")

    alerts = filtered_df[
        filtered_df["risk_level"]
        .isin(["High", "Critical"])
    ].sort_values(
        "timestamp",
        ascending=False
    )

    st.dataframe(
        alerts.head(15),
        use_container_width=True
    )


# =================================================
# NETWORK MONITORING
# =================================================

elif page == "📡 Network Monitoring":

    st.header("📡 Network Telemetry Monitoring")

    st.write(
        "Monitoring network events and communication patterns."
    )

    st.dataframe(
        filtered_df,
        use_container_width=True,
        height=500
    )

    st.subheader(
        "Traffic Volume Analysis"
    )

    fig = px.scatter(
        filtered_df,
        x="timestamp",
        y="bytes",
        size="bytes",
        hover_data=[
            "source_ip",
            "destination_ip",
            "event_type",
            "risk_level"
        ],
        title="Network Traffic Activity"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.subheader(
        "Top Communicating Source IPs"
    )

    ip_counts = (
        filtered_df["source_ip"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    ip_counts.columns = [
        "Source IP",
        "Event Count"
    ]

    fig = px.bar(
        ip_counts,
        x="Source IP",
        y="Event Count",
        title="Top Source IP Activity"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# =================================================
# THREAT DETECTION
# =================================================

elif page == "🚨 Threat Detection":

    st.header("🚨 AI Threat Detection Center")

    st.caption(
        "Known Threat Detection + AI-Based Anomaly Detection"
    )

    # -----------------------------------
    # METRICS
    # -----------------------------------

    total_threats = len(
        filtered_df[
            filtered_df["known_threat"] == True
        ]
    )

    anomalies = len(
        filtered_df[
            filtered_df["is_anomaly"] == True
        ]
    )

    high_risk = len(
        filtered_df[
            filtered_df["ai_risk_level"]
            .isin(["High", "Critical"])
        ]
    )

    avg_risk = round(
        filtered_df["risk_score"].mean(),
        1
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Known Threats",
        total_threats
    )

    col2.metric(
        "AI Anomalies",
        anomalies
    )

    col3.metric(
        "High Risk Events",
        high_risk
    )

    col4.metric(
        "Average Risk Score",
        avg_risk
    )

    st.divider()

    # -----------------------------------
    # HIGH RISK EVENTS
    # -----------------------------------

    st.subheader(
        "🔥 High Priority Threats"
    )

    high_risk_events = filtered_df[
        filtered_df["ai_risk_level"]
        .isin(["High", "Critical"])
    ].sort_values(
        "risk_score",
        ascending=False
    )

    display_columns = [

        "timestamp",

        "source_ip",

        "destination_ip",

        "event_type",

        "threat_type",

        "is_anomaly",

        "risk_score",

        "ai_risk_level",

        "mitre_tactic",

        "mitre_technique"
    ]

    st.dataframe(
        high_risk_events[
            display_columns
        ],
        use_container_width=True
    )

    st.divider()

    # -----------------------------------
    # THREAT DISTRIBUTION
    # -----------------------------------

    col1, col2 = st.columns(2)

    with col1:

        threat_counts = (
            filtered_df[
                filtered_df["known_threat"]
                == True
            ]["threat_type"]
            .value_counts()
            .reset_index()
        )

        threat_counts.columns = [
            "Threat Type",
            "Count"
        ]

        fig = px.bar(
            threat_counts,
            x="Threat Type",
            y="Count",
            title="Known Threat Distribution"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with col2:

        anomaly_counts = (
            filtered_df["is_anomaly"]
            .value_counts()
            .reset_index()
        )

        anomaly_counts.columns = [
            "AI Detection",
            "Count"
        ]

        anomaly_counts[
            "AI Detection"
        ] = anomaly_counts[
            "AI Detection"
        ].map({
            True: "Anomaly",
            False: "Normal"
        })

        fig = px.pie(
            anomaly_counts,
            names="AI Detection",
            values="Count",
            title="AI Behaviour Analysis"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    st.divider()

    # -----------------------------------
    # MITRE MAPPING
    # -----------------------------------

    st.subheader(
        "🎯 MITRE ATT&CK Intelligence"
    )

    mitre_data = filtered_df[
        filtered_df["mitre_tactic"]
        != "Unknown"
    ][
        [
            "event_type",
            "threat_type",
            "mitre_tactic",
            "mitre_technique",
            "risk_score"
        ]
    ]

    st.dataframe(
        mitre_data,
        use_container_width=True
    )


elif page == "🕸️ Attack Graph":

    st.header("🕸️ Dynamic Attack Graph")

    st.caption(
        "AI-driven visualization of suspicious network relationships and potential attack paths"
    )

    # -----------------------------------
    # GRAPH SUMMARY
    # -----------------------------------

    summary = get_graph_summary(
        attack_graph
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Network Nodes",
        summary["total_nodes"]
    )

    col2.metric(
        "Connections",
        summary["total_connections"]
    )

    col3.metric(
        "Suspicious Nodes",
        summary["suspicious_nodes"]
    )

    col4.metric(
        "Critical Assets",
        summary["critical_assets"]
    )

    st.divider()

    # -----------------------------------
    # NETWORK GRAPH
    # -----------------------------------

    st.subheader(
        "Network Relationship Graph"
    )

    import matplotlib.pyplot as plt
    import networkx as nx

    graph_to_draw = attack_graph

    pos = nx.spring_layout(
        graph_to_draw,
        seed=42
    )

    suspicious_nodes = get_suspicious_nodes(
        graph_to_draw
    )

    critical_nodes = get_critical_assets(
        graph_to_draw
    )

    normal_nodes = [
        node
        for node in graph_to_draw.nodes()
        if node not in suspicious_nodes
        and node not in critical_nodes
    ]

    plt.figure(
        figsize=(12, 8)
    )

    # Normal nodes
    nx.draw_networkx_nodes(
        graph_to_draw,
        pos,
        nodelist=normal_nodes,
        node_size=500
    )

    # Suspicious nodes
    nx.draw_networkx_nodes(
        graph_to_draw,
        pos,
        nodelist=suspicious_nodes,
        node_size=700
    )

    # Critical nodes
    nx.draw_networkx_nodes(
        graph_to_draw,
        pos,
        nodelist=critical_nodes,
        node_size=900
    )

    # Edges
    nx.draw_networkx_edges(
        graph_to_draw,
        pos,
        arrows=True,
        alpha=0.5
    )

    # Labels
    nx.draw_networkx_labels(
        graph_to_draw,
        pos,
        font_size=8
    )

    plt.axis("off")

    st.pyplot(
        plt
    )

    st.divider()

    # -----------------------------------
    # ATTACK PATH ANALYSIS
    # -----------------------------------

    st.subheader(
        "🔮 Potential Multi-Step Attack Paths"
    )

    attack_paths = find_attack_paths(
        attack_graph
    )

    if attack_paths:

        for i, path in enumerate(
            attack_paths,
            start=1
        ):

            st.markdown(
                f"### Attack Path {i}"
            )

            st.write(
                "  ➜  ".join(path)
            )

    else:

        st.success(
            "No multi-step attack path detected."
        )


elif page == "🔮 Attack Forecast":

    st.header("🔮 Multi-Step Attack Forecasting")

    st.caption(
        "AI-assisted prediction of the next likely attack stage"
    )

    

    # -----------------------------------
    # GENERATE FORECAST
    # -----------------------------------

    suspicious_ips = (
    df[
        df["ai_risk_level"]
        .isin(["High", "Critical"])
    ]["source_ip"]
    .unique())

    selected_ip = st.selectbox(
    "Select Suspicious Source / Attacker",
    suspicious_ips)
    forecast = forecast_next_attack(
    df,
    selected_ip)

    forecast = forecast_next_attack(df)

    # -----------------------------------
    # DISPLAY RESULT
    # -----------------------------------

    if forecast["prediction"] is None:

        st.warning(
            forecast["status"]
        )

    else:

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Observed Stage",
            forecast["observed_stage"]
        )

        col2.metric(
            "Predicted Next Stage",
            forecast["next_stage"]
        )

        col3.metric(
            "Prediction Confidence",
            f'{forecast["confidence"]}%'
        )

        st.divider()

        # -----------------------------------
        # MAIN PREDICTION
        # -----------------------------------

        st.subheader(
            "🔮 AI Attack Forecast"
        )

        st.success(
            f"""
            Predicted Activity:
            {forecast["prediction"]}
            """
        )

        st.write(
            f"""
            Based on the observed attack progression,
            the system predicts **{forecast["prediction"]}**
            as the next likely attack activity.
            """
        )

        st.divider()

        # -----------------------------------
        # ATTACK SOURCE
        # -----------------------------------

        st.subheader(
            "🎯 Associated Network Context"
        )

        col1, col2 = st.columns(2)

        col1.write(
            f"**Source:** {forecast['source_ip']}"
        )

        col2.write(
            f"**Latest Target:** {forecast['target_ip']}"
        )

        st.divider()

        # -----------------------------------
        # ATTACK TIMELINE
        # -----------------------------------

        st.subheader(
            "📈 Observed Attack Sequence"
        )

        timeline = get_attack_timeline(df)

        if timeline:

            timeline_df = pd.DataFrame(
                timeline
            )

            st.dataframe(
                timeline_df,
                use_container_width=True
            )