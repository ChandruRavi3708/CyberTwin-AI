import streamlit as st
import pandas as pd
import plotly.express as px


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
        "🚨 Threat Detection"
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

    st.header("🚨 Threat Detection Center")

    st.info(
        "Day 1: Rule-based suspicious event identification."
    )

    suspicious_events = filtered_df[
        filtered_df["risk_level"]
        .isin(["High", "Critical"])
    ]

    col1, col2 = st.columns(2)

    with col1:

        st.metric(
            "Suspicious Events",
            len(suspicious_events)
        )


    with col2:

        st.metric(
            "Critical Threats",
            len(
                suspicious_events[
                    suspicious_events[
                        "risk_level"
                    ] == "Critical"
                ]
            )
        )


    st.subheader(
        "Detected Suspicious Activity"
    )

    st.dataframe(
        suspicious_events.sort_values(
            "timestamp",
            ascending=False
        ),
        use_container_width=True
    )


    st.subheader(
        "Threat Type Distribution"
    )

    threat_counts = (
        suspicious_events["event_type"]
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
        title="Detected Threat Activity"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )