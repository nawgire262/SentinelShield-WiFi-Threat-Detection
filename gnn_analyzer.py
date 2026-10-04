import numpy as np

try:
    import networkx as nx
except ImportError:
    nx = None

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
except ImportError:
    torch = None
    nn = None
    F = None


class GraphAnalyzer:
    def __init__(self):
        self.enabled = nx is not None
        if self.enabled:
            self.graph = nx.Graph()
        else:
            self.graph = None

    def ingest_network(self, network_records):
        if not self.enabled:
            return
        self.graph.clear()
        for rec in network_records:
            source = rec.get('SSID') or rec.get('BSSID')
            if not source:
                continue
            self.graph.add_node(source, risk=rec.get('Combined_Risk', 0), rssi=rec.get('RSSI', 0))
            if rec.get('Connected_Client'):
                self.graph.add_node(rec['Connected_Client'], risk=0)
                self.graph.add_edge(source, rec['Connected_Client'], weight=abs(rec.get('RSSI', 0)))

    def highest_risk_nodes(self, top_n=10):
        if not self.enabled:
            return []
        return sorted(
            [(n, d.get('risk', 0)) for n, d in self.graph.nodes(data=True)],
            key=lambda item: item[1],
            reverse=True
        )[:top_n]

    def graph_summary(self):
        if not self.enabled:
            return {"nodes": 0, "edges": 0, "avg_degree": 0}
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "avg_degree": sum(dict(self.graph.degree()).values()) / max(1, self.graph.number_of_nodes()),
        }


class SequenceAnomalyDetector:
    def __init__(self):
        self.window = []
        self.max_window = 50

    def ingest(self, record):
        self.window.append(record)
        if len(self.window) > self.max_window:
            self.window.pop(0)

    def score(self):
        if len(self.window) < 2:
            return 0.0
        rssis = np.array([r.get('RSSI', -100) for r in self.window], dtype=float)
        diffs = np.abs(np.diff(rssis))
        return float(np.mean(diffs) * 2.5)

    def detect_burst(self):
        if len(self.window) < 3:
            return False
        counters = [r.get('Deauth_Count', 0) for r in self.window]
        return max(counters) > 15


if torch is not None:
    class SimpleGNN(nn.Module):
        def __init__(self, input_dim=16, hidden_dim=32, output_dim=1):
            super().__init__()
            self.lin1 = nn.Linear(input_dim, hidden_dim)
            self.lin2 = nn.Linear(hidden_dim, output_dim)

        def forward(self, x, edge_index):
            x = F.relu(self.lin1(x))
            x = self.lin2(x)
            return torch.sigmoid(x)
