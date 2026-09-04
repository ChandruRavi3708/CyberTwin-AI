import pandas as pd
import random
from datetime import datetime, timedelta


# ---------------------------------------
# CONFIGURATION
# ---------------------------------------

NUM_EVENTS = 1000

START_TIME = datetime(2026, 9, 1, 8, 0, 0)

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.15",
    "192.168.1.20",
    "192.168.1.25",
    "192.168.1.30",
    "192.168.1.40",
    "192.168.1.50",
    "192.168.1.60"
]

SUSPICIOUS_IPS = [
    "185.220.101.10",
    "45.142.212.55",
    "91.108.4.100"
]

INTERNAL_SERVERS = [
    "192.168.1.20",
    "192.168.1.30",
    "192.168.1.50",
    "192.168.1.60"
]

events = []


# ---------------------------------------
# HELPER FUNCTION
# ---------------------------------------

def add_event(
    timestamp,
    source_ip,
    destination_ip,
    protocol,
    bytes_sent,
    failed_logins,
    port,
    event_type,
    risk_level
):

    events.append({
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "bytes": bytes_sent,
        "failed_logins": failed_logins,
        "port": port,
        "event_type": event_type,
        "risk_level": risk_level
    })


# ---------------------------------------
# GENERATE EVENTS
# ---------------------------------------

current_time = START_TIME

for i in range(NUM_EVENTS):

    current_time += timedelta(
        seconds=random.randint(5, 60)
    )

    event_category = random.choices(
        [
            "normal",
            "dns",
            "web",
            "port_scan",
            "login_failure",
            "suspicious_connection",
            "lateral_movement",
            "data_exfiltration"
        ],
        weights=[
            55,
            15,
            12,
            5,
            5,
            4,
            3,
            1
        ]
    )[0]


    # ---------------------------------------
    # NORMAL TRAFFIC
    # ---------------------------------------

    if event_category == "normal":

        add_event(
            current_time,
            random.choice(NORMAL_IPS),
            random.choice(INTERNAL_SERVERS),
            random.choice(["TCP", "UDP"]),
            random.randint(500, 5000),
            0,
            random.choice([80, 443]),
            "normal",
            "Low"
        )


    # ---------------------------------------
    # DNS
    # ---------------------------------------

    elif event_category == "dns":

        add_event(
            current_time,
            random.choice(NORMAL_IPS),
            "8.8.8.8",
            "UDP",
            random.randint(100, 800),
            0,
            53,
            "dns_request",
            "Low"
        )


    # ---------------------------------------
    # WEB
    # ---------------------------------------

    elif event_category == "web":

        add_event(
            current_time,
            random.choice(NORMAL_IPS),
            random.choice(INTERNAL_SERVERS),
            "TCP",
            random.randint(1000, 10000),
            0,
            random.choice([80, 443]),
            "web_request",
            "Low"
        )


    # ---------------------------------------
    # PORT SCAN
    # ---------------------------------------

    elif event_category == "port_scan":

        add_event(
            current_time,
            random.choice(SUSPICIOUS_IPS),
            random.choice(INTERNAL_SERVERS),
            "TCP",
            random.randint(50, 300),
            0,
            random.choice([
                21, 22, 23, 25, 80,
                110, 443, 445, 3389
            ]),
            "port_scan",
            "Medium"
        )


    # ---------------------------------------
    # LOGIN FAILURE
    # ---------------------------------------

    elif event_category == "login_failure":

        add_event(
            current_time,
            random.choice(SUSPICIOUS_IPS),
            random.choice(INTERNAL_SERVERS),
            "TCP",
            random.randint(100, 500),
            random.randint(3, 15),
            22,
            "login_failure",
            random.choice(["High", "Critical"])
        )


    # ---------------------------------------
    # SUSPICIOUS CONNECTION
    # ---------------------------------------

    elif event_category == "suspicious_connection":

        add_event(
            current_time,
            random.choice(SUSPICIOUS_IPS),
            random.choice(INTERNAL_SERVERS),
            "TCP",
            random.randint(5000, 20000),
            random.randint(0, 3),
            random.choice([445, 3389]),
            "suspicious_connection",
            "High"
        )


    # ---------------------------------------
    # LATERAL MOVEMENT
    # ---------------------------------------

    elif event_category == "lateral_movement":

        add_event(
            current_time,
            random.choice(NORMAL_IPS),
            random.choice(INTERNAL_SERVERS),
            "TCP",
            random.randint(5000, 30000),
            random.randint(0, 3),
            random.choice([445, 3389]),
            "lateral_movement",
            "Critical"
        )


    # ---------------------------------------
    # DATA EXFILTRATION
    # ---------------------------------------

    elif event_category == "data_exfiltration":

        add_event(
            current_time,
            random.choice(INTERNAL_SERVERS),
            random.choice(SUSPICIOUS_IPS),
            "TCP",
            random.randint(50000, 250000),
            0,
            443,
            "data_exfiltration",
            "Critical"
        )


# ---------------------------------------
# CREATE DATAFRAME
# ---------------------------------------

df = pd.DataFrame(events)

df.to_csv(
    "data/network_events.csv",
    index=False
)

print(
    f"Successfully generated {len(df)} network events."
)