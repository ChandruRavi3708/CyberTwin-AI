import pandas as pd


# --------------------------------------------------
# ATTACK STAGE TRANSITION MODEL
# --------------------------------------------------

ATTACK_TRANSITIONS = {

    "Reconnaissance": [
        {
            "next_stage": "Credential Access",
            "confidence": 0.75,
            "prediction": "Credential Attack"
        },
        {
            "next_stage": "Initial Access",
            "confidence": 0.60,
            "prediction": "Suspicious Access Attempt"
        }
    ],

    "Credential Access": [
        {
            "next_stage": "Lateral Movement",
            "confidence": 0.82,
            "prediction": "Lateral Movement"
        },
        {
            "next_stage": "Persistence",
            "confidence": 0.65,
            "prediction": "Persistent Access"
        }
    ],

    "Lateral Movement": [
        {
            "next_stage": "Collection",
            "confidence": 0.78,
            "prediction": "Sensitive Data Collection"
        },
        {
            "next_stage": "Exfiltration",
            "confidence": 0.88,
            "prediction": "Data Exfiltration"
        }
    ],

    "Collection": [
        {
            "next_stage": "Exfiltration",
            "confidence": 0.90,
            "prediction": "Data Exfiltration"
        }
    ],

    "Exfiltration": [
        {
            "next_stage": "Impact",
            "confidence": 0.50,
            "prediction": "Potential Business Impact"
        }
    ]
}


# --------------------------------------------------
# GET ATTACK TIMELINE
# --------------------------------------------------

def get_attack_timeline(df):

    suspicious_df = df[
        df["known_threat"] == True
    ].copy()

    suspicious_df = suspicious_df.sort_values(
        "timestamp"
    )

    timeline = []

    for _, row in suspicious_df.iterrows():

        tactic = row["mitre_tactic"]

        if tactic != "Unknown":

            timeline.append({

                "timestamp":
                row["timestamp"],

                "source_ip":
                row["source_ip"],

                "destination_ip":
                row["destination_ip"],

                "threat_type":
                row["threat_type"],

                "mitre_tactic":
                tactic,

                "risk_score":
                row["risk_score"]
            })

    return timeline


# --------------------------------------------------
# FORECAST NEXT ATTACK
# --------------------------------------------------

def forecast_next_attack(df, source_ip=None):

    working_df = df.copy()

    # Filter by attacker/source IP

    if source_ip is not None:

        working_df = working_df[
            working_df["source_ip"] == source_ip
        ]


    timeline = get_attack_timeline(
        working_df
    )


    if len(timeline) == 0:

        return {
            "status": "No attack sequence detected",
            "prediction": None,
            "confidence": 0,
            "observed_stage": None
        }


    latest_event = timeline[-1]

    current_stage = latest_event[
        "mitre_tactic"
    ]


    if current_stage not in ATTACK_TRANSITIONS:

        return {
            "status": "No prediction available",
            "prediction": None,
            "confidence": 0,
            "observed_stage": current_stage
        }


    possible_predictions = (
        ATTACK_TRANSITIONS[
            current_stage
        ]
    )


    prediction = max(
        possible_predictions,
        key=lambda x: x["confidence"]
    )


    risk_score = latest_event[
        "risk_score"
    ]


    adjusted_confidence = (
        prediction["confidence"]
        +
        (risk_score / 100) * 0.10
    )


    adjusted_confidence = min(
        adjusted_confidence,
        0.99
    )


    return {

        "status":
        "Prediction Generated",

        "observed_stage":
        current_stage,

        "prediction":
        prediction["prediction"],

        "next_stage":
        prediction["next_stage"],

        "confidence":
        round(
            adjusted_confidence * 100,
            1
        ),

        "source_ip":
        latest_event["source_ip"],

        "target_ip":
        latest_event["destination_ip"]
    }