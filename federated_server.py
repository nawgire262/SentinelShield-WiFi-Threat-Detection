# federated_server.py
import json
import base64
try:
    import numpy as np
except ImportError:
    np = None
try:
    import torch
except ImportError:
    torch = None
from collections import OrderedDict

class FederatedMeshAggregator:
    def __init__(self):
        self.registered_payloads = []

    def load_node_payload(self, payload_file_path):
        """Decodes raw base64 structural update payloads from mesh edge instances."""
        try:
            with open(payload_file_path, "r") as f:
                meta = json.load(f)
            
            decoded_bytes = base64.b64decode(meta["payload"])
            payload_data = json.loads(decoded_bytes.decode('utf-8'))
            self.registered_payloads.append(payload_data)
            return True
        except Exception as e:
            return False

    def execute_federated_averaging(self, base_model):
        """Executes the FedAvg mathematical algorithm across the encrypted updates matrix."""
        if not self.registered_payloads:
            return base_model.state_dict()

        if np is None or torch is None:
            raise RuntimeError("Federated averaging requires both numpy and torch to be installed.")

        global_state = OrderedDict()
        total_nodes = len(self.registered_payloads)
        first_payload = self.registered_payloads[0]["model_weights"]

        # Step through every tensor layer matrix configuration
        for layer_key in first_payload.keys():
            layer_tensors = []
            
            for node_data in self.registered_payloads:
                node_weight = np.array(node_data["model_weights"][layer_key])
                layer_tensors.append(node_weight)
                
            # Compute the mathematical average update for this tensor block layer
            mean_layer = np.mean(layer_tensors, axis=0)
            global_state[layer_key] = torch.FloatTensor(mean_layer)

        # Clear active memory buffer
        self.registered_payloads = []
        return global_state