"""
Example: End-to-End Model Hashing Demo with MrkleTree

This script demonstrates:
1. Generating a binary tensor file (`toy.bt`) from a toy model.
2. Loading and hashing the model parameters using MrkleTree.

Usage:
    python toy_demo.py --generate   # Create toy.bt
    python toy_demo.py --hash       # Load and compute Merkle root
"""

import time
import argparse
import torch
import numpy as np
from bintensors.numpy import save_file, load_file
from mrkle import MrkleTree


class ToyModel(torch.nn.Module):
    """A simple feedforward model used for demonstration."""

    def __init__(self, in_feature: int, out_feature: int):
        super().__init__()
        self.ln = torch.nn.Linear(in_feature, out_feature)
        self.output = torch.nn.Linear(out_feature, 1)

    def forward(self, x: torch.Tensor):
        x = self.ln(x)
        logits = self.output(torch.tanh(x))
        return logits, torch.sigmoid(x)


def namespaced_state_dict(model: torch.nn.Module) -> dict[str, np.ndarray]:
    """
    Convert model parameters to a namespaced NumPy dict.
    Example key: "toymodel.ln.weight"
    """
    state_dict = model.state_dict()
    return {
        f"{model.__class__.__name__.lower()}.{k}": v.cpu().numpy()
        for k, v in state_dict.items()
    }


def generate_toy_bt(path: str = "toy.bt"):
    """Generate a binary tensor file for the ToyModel."""
    model = ToyModel(10, 10)
    state = namespaced_state_dict(model)
    save_file(state, path)
    print(f"✅ Generated {path} successfully.")


def hash_toy_bt(path: str = "toy.bt"):
    """Load toy.bt and compute the Merkle root."""
    print(f"🔍 Loading {path}...")
    start = time.perf_counter()
    state_dict = load_file(path)
    tree = MrkleTree.from_dict(state_dict, name="sha224", format="flatten")
    elapsed = time.perf_counter() - start
    print(f"⏱ Execution time (load + hash): {elapsed:.5f} seconds")

    if root := tree.root():
        print(f"🌳 Module Root Hash: {root.hex()}")
        json_path = f"toy-{root[0:2].hex()}.json"
        with open(json_path, "wb") as f:
            tree.dumps(f)
        print(f"📄 Merkle tree exported to {json_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ToyModel + MrkleTree demo")
    parser.add_argument(
        "--generate", action="store_true", help="Generate toy.bt binary tensor file"
    )
    parser.add_argument(
        "--hash", action="store_true", help="Compute Merkle hash from toy.bt"
    )
    args = parser.parse_args()

    if args.generate:
        generate_toy_bt()
    elif args.hash:
        hash_toy_bt()
    else:
        parser.print_help()
