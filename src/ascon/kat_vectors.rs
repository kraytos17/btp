extern crate alloc;

#[allow(clippy::empty_line_after_doc_comments)]
/// NIST SP 800-232 (Final, August 2025) Known Answer Test vectors for ASCON-AEAD128.
///
/// Source: <https://github.com/ascon/ascon-c/blob/main/crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt>
/// Format: Official SUPERCOP KAT format with Count, Key, Nonce, PT, AD, CT fields.

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct AsconKatVector {
    pub count: usize,
    pub key: [u8; 16],
    pub nonce: [u8; 16],
    pub pt: alloc::vec::Vec<u8>,
    pub ad: alloc::vec::Vec<u8>,
    pub ct: alloc::vec::Vec<u8>,
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
#[allow(clippy::similar_names, clippy::items_after_statements)]
#[must_use]
pub fn parse_kat_file(contents: &str) -> alloc::vec::Vec<AsconKatVector> {
    let mut vectors = alloc::vec::Vec::new();
    let mut current_count: Option<usize> = None;
    let mut current_key: Option<[u8; 16]> = None;
    let mut current_nonce: Option<[u8; 16]> = None;
    let mut current_pt: Option<alloc::vec::Vec<u8>> = None;
    let mut current_ad: Option<alloc::vec::Vec<u8>> = None;
    let mut current_ct: Option<alloc::vec::Vec<u8>> = None;

    fn flush_vector(
        vectors: &mut alloc::vec::Vec<AsconKatVector>,
        count: Option<usize>,
        key: Option<[u8; 16]>,
        nonce: Option<[u8; 16]>,
        pt: Option<alloc::vec::Vec<u8>>,
        ad: Option<alloc::vec::Vec<u8>>,
        ct: Option<alloc::vec::Vec<u8>>,
    ) {
        if let (Some(count), Some(key), Some(nonce), Some(pt), Some(ad), Some(ct)) =
            (count, key, nonce, pt, ad, ct)
        {
            vectors.push(AsconKatVector {
                count,
                key,
                nonce,
                pt,
                ad,
                ct,
            });
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
                current_key,
                current_nonce,
                current_pt.take(),
                current_ad.take(),
                current_ct.take(),
            );
            current_count = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("Key = ") {
            let bytes = parse_hex(rest.trim());
            if bytes.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                current_key = Some(arr);
            }
        } else if let Some(rest) = line.strip_prefix("Nonce = ") {
            let bytes = parse_hex(rest.trim());
            if bytes.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                current_nonce = Some(arr);
            }
        } else if let Some(rest) = line.strip_prefix("PT =") {
            current_pt = Some(parse_hex(rest.trim()));
        } else if let Some(rest) = line.strip_prefix("AD =") {
            current_ad = Some(parse_hex(rest.trim()));
        } else if let Some(rest) = line.strip_prefix("CT =") {
            current_ct = Some(parse_hex(rest.trim()));
        }
    }

    // Flush last vector
    flush_vector(
        &mut vectors,
        current_count,
        current_key,
        current_nonce,
        current_pt,
        current_ad,
        current_ct,
    );

    vectors
}

#[cfg(feature = "std")]
#[must_use]
pub fn load_kat_vectors() -> alloc::vec::Vec<AsconKatVector> {
    let contents = include_str!("../../test_data/LWC_AEAD_KAT_128_128.txt");
    parse_kat_file(contents)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex(""), alloc::vec::Vec::<u8>::new());
        assert_eq!(parse_hex("00"), alloc::vec![0x00]);
        assert_eq!(parse_hex("FF"), alloc::vec![0xFF]);
        assert_eq!(parse_hex("00FF"), alloc::vec![0x00, 0xFF]);
    }

    #[test]
    fn test_parse_kat_sample() {
        let sample = "Count = 1
Key = 000102030405060708090A0B0C0D0E0F
Nonce = 101112131415161718191A1B1C1D1E1F
PT = 
AD = 
CT = 4F9C278211BEC9316BF68F46EE8B2EC6
";
        let vectors = parse_kat_file(sample);
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].count, 1);
        assert_eq!(vectors[0].pt.len(), 0);
        assert_eq!(vectors[0].ad.len(), 0);
        assert_eq!(vectors[0].ct.len(), 16);
    }

    #[test]
    fn test_parse_kat_with_data() {
        let sample = "Count = 34
Key = 000102030405060708090A0B0C0D0E0F
Nonce = 101112131415161718191A1B1C1D1E1F
PT = 20
AD = 
CT = E8DD576ABA1CD3E6FC704DE02AEDB79588
";
        let vectors = parse_kat_file(sample);
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].pt, alloc::vec![0x20]);
        assert_eq!(vectors[0].ad.len(), 0);
        assert_eq!(vectors[0].ct.len(), 17);
    }
}
