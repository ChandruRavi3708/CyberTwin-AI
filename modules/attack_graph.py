import networkx as nx
import pandas as pd


def build_attack_graph(df):

    G = nx.DiGraph()

    # -----------------------------------
    # ADD NETWORK COMMUNICATION EVENTS
    # -----------------------------------

    for _, row in df.iterrows():

        source = row["source_ip"]
        destination = row["destination_ip"]

        risk = row["risk_score"]
        threat = row["threat_type"]

        # -----------------------------------
        # ADD SOURCE NODE
        # -----------------------------------

        if not G.has_node(source):

            G.add_node(
                source,
                node_type="host",
                risk=0
            )

        # -----------------------------------
        # ADD DESTINATION NODE
        # -----------------------------------

        if not G.has_node(destination):

            G.add_node(
                destination,
                node_type="host",
                risk=0
            )

        # -----------------------------------
        # UPDATE NODE RISK
        # -----------------------------------

        G.nodes[source]["risk"] = max(
            G.nodes[source]["risk"],
            risk
        )

        G.nodes[destination]["risk"] = max(
            G.nodes[destination]["risk"],
            risk
        )

        # -----------------------------------
        # ADD / UPDATE CONNECTION
        # -----------------------------------

        if G.has_edge(source, destination):

            G[source][destination]["count"] += 1

            G[source][destination]["risk"] = max(
                G[source][destination]["risk"],
                risk
            )

        else:

            G.add_edge(
                source,
                destination,
                count=1,
                risk=risk,
                threat=threat
            )

    return G


# -----------------------------------
# SUSPICIOUS NODES
# -----------------------------------

def get_suspicious_nodes(G):

    suspicious = []

    for node, data in G.nodes(data=True):

        if data["risk"] >= 60:

            suspicious.append(node)

    return suspicious


# -----------------------------------
# CRITICAL ASSETS
# -----------------------------------

def get_critical_assets(G):

    critical_assets = []

    for node, data in G.nodes(data=True):

        if data["risk"] >= 80:

            critical_assets.append(node)

    return critical_assets


# -----------------------------------
# ATTACK PATH DISCOVERY
# -----------------------------------

def find_attack_paths(G):

    suspicious_nodes = get_suspicious_nodes(G)

    critical_assets = get_critical_assets(G)

    attack_paths = []

    for source in suspicious_nodes:

        for target in critical_assets:

            if source != target:

                try:

                    paths = nx.all_simple_paths(
                        G,
                        source=source,
                        target=target,
                        cutoff=5
                    )

                    for path in paths:

                        attack_paths.append(path)

                        # Limit number of paths
                        if len(attack_paths) >= 10:

                            return attack_paths

                except nx.NetworkXNoPath:

                    pass

    return attack_paths


# -----------------------------------
# GRAPH SUMMARY
# -----------------------------------

def get_graph_summary(G):

    return {

        "total_nodes":
        G.number_of_nodes(),

        "total_connections":
        G.number_of_edges(),

        "suspicious_nodes":
        len(get_suspicious_nodes(G)),

        "critical_assets":
        len(get_critical_assets(G))
    }