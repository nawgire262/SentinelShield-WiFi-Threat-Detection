# anomaly_detector.py
import torch
import torch.nn as nn
import numpy as np

class WirelessBehavioralAutoencoder(nn.Module):
    def __init__(self, sequence_length=10, feature_dimension=4):
        super(WirelessBehavioralAutoencoder, self).__init__()
        
        self.encoder = nn.Sequential(
            nn.Linear(sequence_length * feature_dimension, 32),
            nn.ReLU(),
            nn.Linear(32, 8),
            nn.ReLU()
        )
        
        self.decoder = nn.Sequential(
            nn.Linear(8, 32),
            nn.ReLU(),
            nn.Linear(32, sequence_length * feature_dimension),
            nn.Tanh()
        )

    def forward(self, x):
        batch_size = x.size(0)
        flat_x = x.view(batch_size, -1)
        latent = self.encoder(flat_x)
        reconstruction = self.decoder(latent)
        return reconstruction.view(x.shape)

def calculate_anomaly_reconstruction_error(model, sequence_tensor, threshold=0.15):
    model.eval()
    with torch.no_grad():
        reconstructed = model(sequence_tensor)
        loss = torch.mean((sequence_tensor - reconstructed) ** 2).item()
        
    is_malicious = loss > threshold
    return is_malicious, loss