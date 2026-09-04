import pandas as pd


def preprocess_data(df):

    # Create a copy
    df = df.copy()

    # Convert timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # -----------------------------------
    # TIME FEATURES
    # -----------------------------------

    df["hour"] = df["timestamp"].dt.hour

    df["minute"] = df["timestamp"].dt.minute

    # -----------------------------------
    # NETWORK FEATURES
    # -----------------------------------

    # Logarithmic byte feature
    df["log_bytes"] = (
        df["bytes"] + 1
    ).apply(lambda x: __import__("math").log(x))

    # Is this authentication related?
    df["is_auth_event"] = (
        df["event_type"]
        .isin([
            "login_failure"
        ])
        .astype(int)
    )

    # Is this scanning?
    df["is_scan"] = (
        df["event_type"]
        .isin([
            "port_scan"
        ])
        .astype(int)
    )

    # Is this lateral movement?
    df["is_lateral_movement"] = (
        df["event_type"]
        .isin([
            "lateral_movement"
        ])
        .astype(int)
    )

    # Is this data exfiltration?
    df["is_exfiltration"] = (
        df["event_type"]
        .isin([
            "data_exfiltration"
        ])
        .astype(int)
    )

    return df