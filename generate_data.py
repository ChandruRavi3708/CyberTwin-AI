"""Generate CyberTwin AI's deterministic offline demo dataset."""

from modules.event_generator import save_network_events


if __name__ == "__main__":
    events = save_network_events("data/network_events.csv")
    print(f"Successfully generated {len(events)} network events.")
