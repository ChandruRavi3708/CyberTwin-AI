def calculate_risk(df):

    df = df.copy()

    risk_scores = []

    for _, row in df.iterrows():

        score = 0

        # -----------------------------------
        # KNOWN THREAT
        # -----------------------------------

        if row["known_threat"]:
            score += 30

        # -----------------------------------
        # AI ANOMALY
        # -----------------------------------

        if row["is_anomaly"]:
            score += 25

        # -----------------------------------
        # FAILED LOGINS
        # -----------------------------------

        if row["failed_logins"] >= 5:
            score += 20

        # -----------------------------------
        # PORT SCAN
        # -----------------------------------

        if row["event_type"] == "port_scan":
            score += 15

        # -----------------------------------
        # LATERAL MOVEMENT
        # -----------------------------------

        if row["event_type"] == "lateral_movement":
            score += 35

        # -----------------------------------
        # DATA EXFILTRATION
        # -----------------------------------

        if row["event_type"] == "data_exfiltration":
            score += 40

        # -----------------------------------
        # LARGE DATA TRANSFER
        # -----------------------------------

        if row["bytes"] > 50000:
            score += 20

        # Maximum risk = 100

        score = min(score, 100)

        risk_scores.append(score)

    df["risk_score"] = risk_scores

    # -----------------------------------
    # RISK CATEGORY
    # -----------------------------------

    def get_risk_level(score):

        if score >= 80:
            return "Critical"

        elif score >= 60:
            return "High"

        elif score >= 30:
            return "Medium"

        else:
            return "Low"

    df["ai_risk_level"] = (
        df["risk_score"]
        .apply(get_risk_level)
    )

    return df