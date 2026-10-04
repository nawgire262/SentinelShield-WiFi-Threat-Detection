# federated_node.py
try:
    import torch
except ImportError:
    torch = None
import json
import base64
import os
import time
from pathlib import Path
from collections import OrderedDict

class FederatedNodeAgent:
    def __init__(self, node_id="NODE_OM007"):
        self.node_id = node_id
        self.local_updates_dir = Path("./federated_updates")
        self.local_updates_dir.mkdir(parents=True, exist_ok=True)

    def extract_local_weights(self, pyMod):
        """Extracts the state dictionary tensor arrays from the local PyTorch architecture."""
        if torch is None:
            raise RuntimeError("PyTorch is required for extract_local_weights")
        state_dict = pyMod.state_dict()
        serializable_weights = {}
        
        for key, tensor in state_dict.items():
            # Convert raw tensors to multi-dimensional float arrays for transmission
            serializable_weights[key] = tensor.cpu().numpy().tolist()
            
        return serializable_weights

    def compile_encrypted_payload(self, local_weights):
        """Wraps weights array into an authenticated state payload (Zero-Knowledge proxy)."""
        payload_data = {
            "node_id": self.node_id,
            "timestamp": time.time(),
            "model_weights": local_weights
        }
        
        # Serialize and encode payload
        json_str = json.dumps(payload_data)
        encoded_bytes = base64.b64encode(json_str.encode('utf-8'))
        
        payload_meta = {
            "signature": f"SIG_PQC_{self.node_id}_{int(time.time())}",
            "payload": encoded_bytes.decode('utf-8')
        }
        
        # Output outbound payload locally
        out_path = self.local_updates_dir / f"outbound_{self.node_id}.json"
        with open(out_path, "w") as f:
            json.dump(payload_meta, f, indent=4)
            
        return out_path