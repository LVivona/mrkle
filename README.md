<p align="center">
  <picture>
    <img alt="mrkle" src="https://raw.githubusercontent.com/LVivona/mrkle/refs/heads/main/.github/assets/banner.png" style="max-width: 100%;">
  </picture>
</p>
<p align="center">
  <a href="https://github.com/LVivona/mrkle/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
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
