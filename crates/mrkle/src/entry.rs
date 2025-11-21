use crate::prelude::*;
use crate::{EntryError, IndexType, MrkleNode};

/// Object that holds the bytes hashed `MrkleNode`
/// used for reference of the array.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
#[allow(non_camel_case_types)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct entry {
    bytes: [u8],
}

impl entry {
    /// Try to convert bytes slice into entry object.
    ///
    /// Entry only supports sizes (16, 20, 28, 32, 48, or 64).
    /// These are all the sizes of the sha type crypto algorithms
    #[inline]
    pub fn try_from_bytes(digest: &[u8]) -> Result<&Self, EntryError> {
        match digest.len() {
            16 | 20 | 28 | 32 | 48 | 64 => Ok(
                #[allow(unsafe_code)]
                unsafe {
                    &*(digest as *const [u8] as *const entry)
                },
            ),
            len => Err(EntryError::InvalidByteSliceLength(len)),
        }
    }

    /// Create an entry from the input `value` slice without performing any safety check.
    /// Use only once sure that `value` is a hash of valid length.
    #[inline]
    pub fn from_bytes_unchecked(value: &[u8]) -> &Self {
        Self::from_bytes(value)
    }

    /// Only from code that statically assures correct sizes using array conversions.
    #[inline]
    pub(crate) fn from_bytes(value: &[u8]) -> &Self {
        #[allow(unsafe_code)]
        unsafe {
            &*(value as *const [u8] as *const entry)
        }
    }
}

impl entry {
    /// The first byte of the hash, commonly used to partition a set of object ids.
    #[inline]
    pub fn first_byte(&self) -> u8 {
        self.bytes[0]
    }

    /// Interpret this object id as raw byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the length of the hash in bytes
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return if length of the hash in bytesd is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AsRef<entry> for &entry {
    fn as_ref(&self) -> &entry {
        self
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a entry {
    type Error = EntryError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        entry::try_from_bytes(value)
    }
}

impl<T, D: Digest, Ix: IndexType> PartialEq<MrkleNode<T, D, Ix>> for &entry {
    fn eq(&self, other: &MrkleNode<T, D, Ix>) -> bool {
        *self == other.as_ref()
    }
}

impl entry {
    /// Write ourselves to the `out` in hexadecimal notation, returning the hex-string ready for display.
    ///
    /// **Panics** if the buffer isn't big enough to hold twice as many bytes as the current binary size.
    #[inline]
    #[must_use]
    pub fn hex_to_buffer<'a>(&self, buffer: &'a mut [u8]) -> &'a mut str {
        let num_hex_bytes = self.bytes.len() * 2;
        // Use a simple hex implementation since faster_hex might not be available
        for (i, &byte) in self.bytes.iter().enumerate() {
            let hex_chars = format!("{:02x}", byte);
            buffer[i * 2] = hex_chars.as_bytes()[0];
            buffer[i * 2 + 1] = hex_chars.as_bytes()[1];
        }

        // Convert to string
        str::from_utf8_mut(&mut buffer[..num_hex_bytes]).expect("hex digits are valid UTF-8")
    }

    /// Write ourselves to `out` in hexadecimal notation.
    #[inline]
    #[cfg(feature = "std")]
    pub fn hex_to_writer<W: std::io::Write>(&self, out: &mut W) -> std::io::Result<()> {
        let mut hex_buf = vec![0u8; self.bytes.len() * 2];
        let hex_str = self.hex_to_buffer(&mut hex_buf);
        out.write_all(hex_str.as_bytes())
    }

    /// Return a type which can display itself in hexadecimal form with the `len` amount of characters.
    #[inline]
    pub fn to_hex_with_len(&self, len: usize) -> HexDisplay<'_> {
        HexDisplay {
            inner: self,
            size: len.min(self.bytes.len() * 2), // Cap at actual size
        }
    }

    /// Return a type which displays this entry as hex in full.
    #[inline]
    pub fn to_hex(&self) -> HexDisplay<'_> {
        HexDisplay {
            inner: self,
            size: self.bytes.len() * 2,
        }
    }
}

/// A helper wrapper for displaying an [`entry`] as a
/// hexadecimal string.
///
/// `HexDisplay` provides a view over the raw bytes of an
/// [`entry`], allowing them to be formatted or inspected
/// in human-readable hexadecimal form.
///
/// # Examples
/// ```
/// use mrkle::entry;
/// let entry = entry::from_bytes_unchecked(b"helloworld-bytes");
/// println!("{}", entry.to_hex()); // prints the hex representation
/// ```
///
/// The `size` field specifies how many bytes from the entry
/// are included in the display. This allows you to limit or
/// slice the visible portion of the underlying data.
#[must_use]
pub struct HexDisplay<'id> {
    /// Borrowed reference to the entry being displayed.
    inner: &'id entry,
    /// Number of bytes to display in hexadecimal.
    size: usize,
}

impl core::fmt::Debug for HexDisplay<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "HexDisplay {{ len : {:?}  slice : {:?} }}",
            self.size, self.inner
        )
    }
}

impl core::fmt::Display for HexDisplay<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = vec![0u8; self.size];
        let hex_str = if self.size <= self.inner.bytes.len() * 2 {
            // Truncate if requested size is smaller
            let truncated_bytes = self.size / 2;
            let temp_entry = entry::from_bytes(&self.inner.bytes[..truncated_bytes]);
            temp_entry.hex_to_buffer(&mut buf)
        } else {
            self.inner.hex_to_buffer(&mut buf)
        };
        f.write_str(&hex_str[..self.size.min(hex_str.len())])
    }
}

impl core::fmt::Display for entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "{}", self.to_hex())
    }
}

#[cfg(feature = "serde")]
impl<'de: 'a, 'a> serde::Deserialize<'de> for &'a entry {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct __Visitor<'de: 'a, 'a> {
            marker: core::marker::PhantomData<&'a entry>,
            lifetime: core::marker::PhantomData<&'de ()>,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for __Visitor<'de, 'a> {
            type Value = &'a entry;
            fn expecting(&self, __formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Formatter::write_str(__formatter, "tuple struct Digest")
            }
            #[inline]
            fn visit_newtype_struct<__E>(
                self,
                __e: __E,
            ) -> core::result::Result<Self::Value, __E::Error>
            where
                __E: serde::Deserializer<'de>,
            {
                let __field0: &'a [u8] = match <&'a [u8] as serde::Deserialize>::deserialize(__e) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                Ok(entry::try_from_bytes(__field0).expect("hash of known length"))
            }
            #[inline]
            fn visit_seq<__A>(self, mut __seq: __A) -> core::result::Result<Self::Value, __A::Error>
            where
                __A: serde::de::SeqAccess<'de>,
            {
                let __field0 =
                    match match serde::de::SeqAccess::next_element::<&'a [u8]>(&mut __seq) {
                        Ok(__val) => __val,
                        Err(__err) => {
                            return Err(__err);
                        }
                    } {
                        Some(__value) => __value,
                        None => {
                            return Err(serde::de::Error::invalid_length(
                                0usize,
                                &"tuple struct Digest with 1 element",
                            ));
                        }
                    };
                Ok(entry::try_from_bytes(__field0).expect("hash of known length"))
            }
        }
        serde::Deserializer::deserialize_newtype_struct(
            deserializer,
            "Digest",
            __Visitor {
                marker: core::marker::PhantomData::<&'a entry>,
                lifetime: core::marker::PhantomData,
            },
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto::digest::Digest;

    #[test]
    fn test_entry_creation() {
        // Test valid sizes
        let digest20 = vec![0u8; 20]; // SHA1
        let e20 = entry::try_from_bytes(&digest20).unwrap();
        assert_eq!(e20.len(), 20);

        let digest32 = vec![0u8; 32]; // SHA256
        let e32 = entry::try_from_bytes(&digest32).unwrap();
        assert_eq!(e32.len(), 32);

        // Test invalid size
        let invalid = vec![0u8; 15];
        assert!(entry::try_from_bytes(&invalid).is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_hex_display() {
        let digest = vec![0xde, 0xad, 0xbe, 0xef]; // Not a valid hash size, but for testing

        // Using from_bytes_unchecked for test
        let e = entry::from_bytes_unchecked(&digest);

        let hex_full = format!("{}", e.to_hex());
        assert_eq!(hex_full, "deadbeef");

        let hex_partial = format!("{}", e.to_hex_with_len(4)); // 2 bytes = 4 hex chars
        assert_eq!(hex_partial, "dead");
    }

    #[test]
    fn test_actual_hash() {
        use sha1::Sha1;
        // Create actual hash
        let src = Sha1::digest(b"hello world");
        let mut result = [0u8; 20];
        result.copy_from_slice(&src);

        let e = entry::try_from_bytes(&result).unwrap();
        assert_eq!(e.len(), 20);
        assert_eq!(e.first_byte(), result[0]);
    }

    #[test]
    fn test_with_sha256() {
        use sha2::Sha256;
        let src = Sha256::digest(b"test data");
        let mut result = [0u8; 32];
        result.copy_from_slice(&src);

        let e = entry::try_from_bytes(&result).unwrap();
        assert_eq!(e.len(), 32);
    }
}
