<p align="center">
  <picture>
    <img alt="mrkle" src="https://raw.githubusercontent.com/LVivona/mrkle/refs/heads/main/.github/assets/banner.png" style="max-width: 100%;">
  </picture>
</p>
<p align="center">
  <a href="https://github.com/LVivona/mrkle/blob/main/LICENSE-APACHE.md"><img src="https://img.shields.io/badge/license-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/LVivona/mrkle/blob/main/LICENSE-MIT.md"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://crates.io/crates/mrkle"><img alt="Crates.io Version" src="https://img.shields.io/crates/v/mrkle"></a>
  <a href="https://docs.rs/mrkle"><img alt="docs.rs" src="https://img.shields.io/badge/rust-docs.rs-lightgray?logo=rust&logoColor=orange"></a>
  <a href="https://pypi.org/project/mrkle/"><img alt="PyPI" src="https://img.shields.io/pypi/v/mrkle"></a>
  <a href="https://pypi.org/project/mrkle/"><img alt="Python Version" src="https://img.shields.io/pypi/pyversions/mrkle?logo=python"></a>
</p>


A fast and flexible Merkle Tree library for Rust, providing efficient construction of Merkle Trees, verification of Merkle Proofs for single and multiple elements, and generic support for any hashable data type.

### What is a Merkle Tree?
A Merkle Tree is a tree data structure. where it contains a set of properties such as:

- Each leaf node contains the hash of a data block
- Each non-leaf node contains the hash of its child nodes
- The root hash represents a cryptographic fingerprint of all the data in the tree

This data structure enables efficient and secure verification that a data element is part of a larger dataset without needing to download the entire dataset.

### Use Cases

* Blockchain & Cryptocurrencies: Bitcoin and other cryptocurrencies use Merkle Trees to efficiently verify transactions
* Distributed Systems: Verify data integrity across distributed networks
* File Systems: Git uses Merkle Trees to track changes and verify repository integrity
* Database Verification: Ensure data hasn't been tampered with
* Peer-to-Peer Networks: Verify chunks of data in distributed file sharing


### Example

```python
import torch
from mrkle import MrkleTree

def namespaced_state_dict(model: torch.nn.Module) -> dict[str, torch.Tensor]:
    """
    Returns a state_dict with the model name prefixed to every key.
    """
    sd = model.state_dict()
    return {f"{model.__class__.__name__.lower()}.{k}": v.detach().cpu().numpy() for k, v in sd.items()}

class ToyModel(torch.nn.Module):
    def __init__(self, in_feature: int, out_feature: int):
        super().__init__()
        self.ln = torch.nn.Linear(in_feature, out_feature)
        self.output = torch.nn.Linear(out_feature, 1)

    def forward(self, x: torch.Tensor):
        x = self.ln(x)
        logits = self.output(torch.tanh(x))
        return logits, torch.sigmoid(x)

# Create model + state dict
model = ToyModel(10, 10)
state_dict = namespaced_state_dict(model)

# Construct Merkle tree over model parameters
tree = MrkleTree.from_dict(state_dict, name="sha256", fmt="flatten")

# Root hash identifies the entire model uniquely
print(tree.root())
```

Construct a basic binary Merkle Tree by chunking data into byte slices:

```rust
use mrkle::MrkleTree;
use sha2::Sha256;

// Input data (could also be read from a file)
let data = b"The quick brown fox jumps over the lazy dog. \
                 This is some extra data to make it larger. \
                 Merkle trees are cool!";

// Split into fixed-size chunks
let chunk_size = 16;
let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

// Build the Merkle tree from chunks
let tree = MrkleTree::<&[u8], Sha256>::from(chunks);

// Get the Merkle root
let root = tree.root();
```
