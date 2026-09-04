def map_to_mitre(df):

    df = df.copy()

    mitre_mapping = {

        "Port Scan / Reconnaissance":
        {
            "tactic": "Reconnaissance",
            "technique": "Network Service Scanning"
        },

        "Credential Attack":
        {
            "tactic": "Credential Access",
            "technique": "Brute Force"
        },

        "Lateral Movement":
        {
            "tactic": "Lateral Movement",
            "technique": "Remote Services"
        },

        "Data Exfiltration":
        {
            "tactic": "Exfiltration",
            "technique": "Exfiltration Over Web Service"
        }

    }

    tactics = []
    techniques = []

    for _, row in df.iterrows():

        threat = row["threat_type"]

        if threat in mitre_mapping:

            tactics.append(
                mitre_mapping[threat]["tactic"]
            )

            techniques.append(
                mitre_mapping[threat]["technique"]
            )

        else:

            tactics.append("Unknown")

            techniques.append("Unknown")

    df["mitre_tactic"] = tactics

    df["mitre_technique"] = techniques

    return df