// #![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub use crypto::digest::Digest;

mod builder;
mod hasher;
mod iter;

pub mod entry;
pub mod error;

pub use hasher::{Hasher, MrkleHasher};

pub struct MrkleTree {}
