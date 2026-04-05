extern crate alloc;

#[allow(clippy::empty_line_after_doc_comments)]
/// NIST SP 800-232 (Final, August 2025) Known Answer Test vectors for ASCON-Hash256.
///
/// Source: <https://github.com/ascon/ascon-c/blob/main/crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt>

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct AsconHashKatVector {
    pub count: usize,
    pub msg: alloc::vec::Vec<u8>,
    pub hash: alloc::vec::Vec<u8>,
}

#[cfg(feature = "std")]
fn parse_hex(s: &str) -> alloc::vec::Vec<u8> {
    let s = s.trim();
    if s.is_empty() {
        return alloc::vec::Vec::new();
    }

    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect()
}

#[cfg(feature = "std")]
#[allow(clippy::items_after_statements)]
#[must_use]
pub fn parse_hash_kat_file(contents: &str) -> alloc::vec::Vec<AsconHashKatVector> {
    let mut vectors = alloc::vec::Vec::new();
    let mut current_count: Option<usize> = None;
    let mut current_msg: Option<alloc::vec::Vec<u8>> = None;
    let mut current_hash: Option<alloc::vec::Vec<u8>> = None;

    fn flush_vector(
        vectors: &mut alloc::vec::Vec<AsconHashKatVector>,
        count: Option<usize>,
        msg: Option<alloc::vec::Vec<u8>>,
        hash: Option<alloc::vec::Vec<u8>>,
    ) {
        if let (Some(count), Some(msg), Some(hash)) = (count, msg, hash) {
            vectors.push(AsconHashKatVector { count, msg, hash });
        }
    }

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("Count = ") {
            flush_vector(
                &mut vectors,
                current_count,
                current_msg.take(),
                current_hash.take(),
            );
            current_count = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("Msg =") {
            current_msg = Some(parse_hex(rest.trim()));
        } else if let Some(rest) = line.strip_prefix("MD =") {
            current_hash = Some(parse_hex(rest.trim()));
        }
    }

    flush_vector(&mut vectors, current_count, current_msg, current_hash);

    vectors
}

#[cfg(feature = "std")]
#[must_use]
pub fn load_hash_kat_vectors() -> alloc::vec::Vec<AsconHashKatVector> {
    let contents = include_str!("../../test_data/LWC_HASH_KAT_256.txt");
    parse_hash_kat_file(contents)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hash_kat_sample() {
        let sample = "Count = 1
Msg =
MD = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
";
        let vectors = parse_hash_kat_file(sample);
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].count, 1);
        assert_eq!(vectors[0].msg.len(), 0);
        assert_eq!(vectors[0].hash.len(), 32);
    }
}
