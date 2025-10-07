__all__ = ["MerkleError", "ProofError", "SerdeError", "TreeError", "NodeError"]

class MerkleError(BaseException):
    """
    Base Exception for all Merkle tree related errors.

    This serves as the root Error type for the mrkle library,
    allowing users to catch all library-specific Errors with a single handler.

    # Example
    ```python
    try:
        pass
    except mrkle.MerkleError as e:
        print(f"Merkle operation failed: {e}")
    ```
    """

    pass

class ProofError(MerkleError):
    """
    Exception raised when Merkle proof operations fail.

    # Example
    ```python
    try:
         pass
    except mrkle.ProofError as e:
        print(f"Proof verification failed: {e}")
    ```
    """

    pass

class SerdeError(MerkleError):
    """
    Exception raised when serialization/deserialization operations fail.

    # Example
    ```python
    try:
         pass
    except mrkle.SerdeError as e:
        print(f"Deserialization failed: {e}")
    ```
    """

    pass

class TreeError(MerkleError):
    """
    Exception raised when Merkle tree operations fail.

    # Example
    ```python
    try:
         pass
    except mrkle.TreeError as e:
        print(f"Tree construction failed: {e}")
    ```
    """

    pass

class NodeError(TreeError):
    """
    Exception raised when Merkle tree node operations fail.

    # Example
    ```python
    try:
         pass
    except mrkle.NodeError as e:
        print(f"Node operation failed: {e}")
    ```
    """

    pass
