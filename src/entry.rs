use crate::error::EntryError;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
#[allow(non_camel_case_types)]
pub struct entry {
    bytes: [u8],
}

impl entry {
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

    /// Return a type which can display itself in hexadecimal form with the `len` amount of characters.
    #[inline]
    pub fn to_hex_with_len(&self, len: usize) -> HexDisplay<'_> {
        HexDisplay {
            inner: self,
            size: len.min(self.bytes.len() * 2), // Cap at actual size
        }
    }

    /// Return a type which displays this oid as hex in full.
    #[inline]
    pub fn to_hex(&self) -> HexDisplay<'_> {
        HexDisplay {
            inner: self,
            size: self.bytes.len() * 2,
        }
    }
}

impl entry {
    /// Write ourselves to the `out` in hexadecimal notation, returning the hex-string ready for display.
    ///
    /// **Panics** if the buffer isn't big enough to hold twice as many bytes as the current binary size.
    #[inline]
    #[must_use]
    pub fn hex_to_buf<'a>(&self, buf: &'a mut [u8]) -> &'a mut str {
        let num_hex_bytes = self.bytes.len() * 2;
        // Use a simple hex implementation since faster_hex might not be available
        for (i, &byte) in self.bytes.iter().enumerate() {
            let hex_chars = format!("{:02x}", byte);
            buf[i * 2] = hex_chars.as_bytes()[0];
            buf[i * 2 + 1] = hex_chars.as_bytes()[1];
        }

        // Convert to string
        std::str::from_utf8_mut(&mut buf[..num_hex_bytes]).expect("hex digits are valid UTF-8")
    }

    /// Write ourselves to `out` in hexadecimal notation.
    #[inline]
    pub fn write_hex_to(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut hex_buf = vec![0u8; self.bytes.len() * 2];
        let hex_str = self.hex_to_buf(&mut hex_buf);
        out.write_all(hex_str.as_bytes())
    }
}

pub struct HexDisplay<'a> {
    inner: &'a entry,
    size: usize,
}

impl std::fmt::Display for HexDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buf = vec![0u8; self.size];
        let hex_str = if self.size <= self.inner.bytes.len() * 2 {
            // Truncate if requested size is smaller
            let truncated_bytes = self.size / 2;
            let temp_entry = entry::from_bytes(&self.inner.bytes[..truncated_bytes]);
            temp_entry.hex_to_buf(&mut buf)
        } else {
            self.inner.hex_to_buf(&mut buf)
        };
        f.write_str(&hex_str[..self.size.min(hex_str.len())])
    }
}

impl std::fmt::Display for entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.to_hex())
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

        // Test hex display
        let hex = format!("{}", e.to_hex());
        assert_eq!(hex.len(), 40); // 20 bytes * 2 hex chars per byte
    }

    #[test]
    fn test_with_sha256() {
        use sha2::Sha256;
        let src = Sha256::digest(b"test data");
        let mut result = [0u8; 32];
        result.copy_from_slice(&src);

        let e = entry::try_from_bytes(&result).unwrap();
        assert_eq!(e.len(), 32);

        let hex = format!("{}", e.to_hex());
        assert_eq!(hex.len(), 64); // 32 bytes * 2
    }
}
