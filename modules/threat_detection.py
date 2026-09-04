import pandas as pd
from sklearn.ensemble import IsolationForest


def detect_anomalies(df):

    df = df.copy()

    # Features used by AI

    features = [
        "bytes",
        "failed_logins",
        "port",
        "hour",
        "log_bytes",
        "is_auth_event",
        "is_scan",
        "is_lateral_movement",
        "is_exfiltration"
    ]

    X = df[features]

    # -----------------------------------
    # ISOLATION FOREST
    # -----------------------------------

    model = IsolationForest(
        contamination=0.10,
        random_state=42
    )

    predictions = model.fit_predict(X)

    anomaly_scores = model.decision_function(X)

    # -----------------------------------
    # SAVE RESULTS
    # -----------------------------------

    df["anomaly_prediction"] = predictions

    df["anomaly_score"] = anomaly_scores

    df["is_anomaly"] = (
        df["anomaly_prediction"] == -1
    )

    return df

def detect_known_threats(df):

    df = df.copy()

    df["known_threat"] = False

    df["threat_type"] = "Normal"

    # -----------------------------------
    # PORT SCAN
    # -----------------------------------

    scan_condition = (
        df["event_type"] == "port_scan"
    )

    df.loc[
        scan_condition,
        "known_threat"
    ] = True

    df.loc[
        scan_condition,
        "threat_type"
    ] = "Port Scan / Reconnaissance"

    # -----------------------------------
    # BRUTE FORCE
    # -----------------------------------

    brute_force_condition = (
        df["failed_logins"] >= 5
    )

    df.loc[
        brute_force_condition,
        "known_threat"
    ] = True

    df.loc[
        brute_force_condition,
        "threat_type"
    ] = "Credential Attack"

    # -----------------------------------
    # LATERAL MOVEMENT
    # -----------------------------------

    lateral_condition = (
        df["event_type"] ==
        "lateral_movement"
    )

    df.loc[
        lateral_condition,
        "known_threat"
    ] = True

    df.loc[
        lateral_condition,
        "threat_type"
    ] = "Lateral Movement"

    # -----------------------------------
    # DATA EXFILTRATION
    # -----------------------------------

    exfiltration_condition = (
        df["event_type"] ==
        "data_exfiltration"
    )

    df.loc[
        exfiltration_condition,
        "known_threat"
    ] = True

    df.loc[
        exfiltration_condition,
        "threat_type"
    ] = "Data Exfiltration"

    return df