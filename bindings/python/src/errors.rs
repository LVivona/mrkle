use pyo3::exceptions::PyException;
use pyo3::prelude::*;

// Base exception for all Merkle tree related errors.
//
// This serves as the root exception type for the mrkle library,
// allowing users to catch all library-specific exceptions with a single handler.
//
// # Example
// ```python
// try:
//     # Some merkle operation
//     pass
// except mrkle.MerkleError as e:
//     print(f"Merkle operation failed: {e}")
// ```
pyo3::create_exception!(
    mrkle,
    MerkleError,
    PyException,
    "Base exception error, encapsulating all Merkle tree operations."
);

// Exception raised when Merkle proof operations fail.
//
// # Example
// ```python
// try:
//      pass
// except mrkle.ProofError as e:
//     print(f"Proof verification failed: {e}")
// ```
pyo3::create_exception!(
    mrkle,
    ProofError,
    MerkleError,
    "Exception raised when Merkle proof operations fail."
);

// Exception raised when Merkle tree operations fail.
//
// # Example
// ```python
// try:
//      pass
// except mrkle.TreeError as e:
//     print(f"Tree construction failed: {e}")
// ```
pyo3::create_exception!(
    mrkle,
    TreeError,
    MerkleError,
    "Exception raised when Merkle tree operations fail."
);

// Exception raised when Merkle tree node operations fail.
//
// # Example
// ```python
// try:
//      pass
// except mrkle.NodeError as e:
//     print(f"Node operation failed: {e}")
// ```
pyo3::create_exception!(
    mrkle,
    NodeError,
    TreeError,
    "Exception raised when Merkle tree node operations fail."
);

// Exception raised when serialization/deserialization operations fail.
//
// # Example
// ```python
// try:
//      pass
// except mrkle.SerdeError as e:
//     print(f"Deserialization failed: {e}")
// ```
pyo3::create_exception!(
    mrkle,
    SerdeError,
    MerkleError,
    "Exception raised when serialization/deserialization operations fail."
);

/// Register all custom exceptions with the Python module.
///
/// This function should be called during module initialization to make
/// all custom exceptions available in Python.
///
/// # Arguments
/// * `m` - parent Python module
///
/// # Returns
/// * `PyResult<()>` - Success or error during registration
#[pymodule]
pub(crate) fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let exce_m = PyModule::new(m.py(), "errors")?;

    exce_m.add("MerkleError", m.py().get_type::<MerkleError>())?;
    exce_m.add("ProofError", exce_m.py().get_type::<ProofError>())?;
    exce_m.add("TreeError", exce_m.py().get_type::<TreeError>())?;
    exce_m.add("NodeError", exce_m.py().get_type::<NodeError>())?;
    exce_m.add("SerdeError", exce_m.py().get_type::<SerdeError>())?;

    m.add_submodule(&exce_m)
}

/// Convenience macro for creating and raising a MerkleError with formatted message.
///
/// # Example
/// ```rust
/// merkle_error!(py, "Invalid leaf count: expected {}, got {}", expected, actual);
/// ```
#[macro_export]
macro_rules! merkle_error {
    ($py:expr, $msg:expr) => {
        MerkleError::new_err($msg)
    };
    ($py:expr, $fmt:expr, $($arg:tt)*) => {
        MerkleError::new_err(format!($fmt, $($arg)*))
    };
}

/// Convenience macro for creating and raising a ProofError with formatted message.
///
/// # Example
/// ```rust
/// proof_error!(py, "Proof verification failed for leaf at index {}", index);
/// ```
#[macro_export]
macro_rules! proof_error {
    ($py:expr, $msg:expr) => {
        ProofError::new_err($msg)
    };
    ($py:expr, $fmt:expr, $($arg:tt)*) => {
        ProofError::new_err(format!($fmt, $($arg)*))
    };
}

/// Convenience macro for creating and raising a MerkleTreeException with formatted message.
///
/// # Example
/// ```rust
/// tree_error!(py, "Cannot build tree with {} leaves", leaf_count);
/// ```
#[macro_export]
macro_rules! tree_error {
    ($py:expr, $msg:expr) => {
        MerkleTreeException::new_err($msg)
    };
    ($py:expr, $fmt:expr, $($arg:tt)*) => {
        MerkleTreeException::new_err(format!($fmt, $($arg)*))
    };
}

/// Convenience macro for creating and raising a MerkleNodeException with formatted message.
///
/// # Example
/// ```rust
/// node_error!(py, "Node at index {} does not exist", index);
/// ```
#[macro_export]
macro_rules! node_error {
    ($py:expr, $msg:expr) => {
        MerkleNodeException::new_err($msg)
    };
    ($py:expr, $fmt:expr, $($arg:tt)*) => {
        MerkleNodeException::new_err(format!($fmt, $($arg)*))
    };
}
