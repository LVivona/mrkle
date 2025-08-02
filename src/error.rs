use thiserror::Error;

#[derive(Error, Debug)]
pub enum MrklBuilderError {
    #[error("Builder requires a partion number.")]
    MissingPartion,
}

/// The error returned when trying to convert a byte slice to an [`oid`] or [`ObjectId`]
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    #[error("Cannot instantiate hash from a digest of length {0}")]
    InvalidByteSliceLength(usize),
}
