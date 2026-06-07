use std::collections::HashMap;

/// Computes the Shannon entropy of the given string in bits per character.
///
/// Returns 0.0 for empty strings. Higher values indicate more randomness;
/// typical high-entropy secrets score above 3.5.
pub fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f32;
    let mut freq: HashMap<u8, u32> = HashMap::new();

    for &byte in s.as_bytes() {
        *freq.entry(byte).or_insert(0) += 1;
    }

    let mut entropy: f32 = 0.0;
    for &count in freq.values() {
        if count == 0 {
            continue;
        }
        let p = count as f32 / len;
        entropy -= p * p.log2();
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_has_zero_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn single_char_repeated_has_zero_entropy() {
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
    }

    #[test]
    fn two_equally_distributed_chars_have_entropy_one() {
        let e = shannon_entropy("abababab");
        assert!((e - 1.0).abs() < 0.01, "expected ~1.0, got {e}");
    }

    #[test]
    fn high_entropy_random_string() {
        // A typical base64 secret should have high entropy.
        let e = shannon_entropy("aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789");
        assert!(e > 4.0, "expected >4.0, got {e}");
    }

    #[test]
    fn low_entropy_word() {
        let e = shannon_entropy("password");
        // "password" has 8 distinct chars in 8 chars = 3.0 bits
        assert!(e > 2.0 && e < 4.0, "expected 2-4, got {e}");
    }
}
