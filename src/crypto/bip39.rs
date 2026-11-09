//! BIP-39 mnemonic phrase handling for recovery keys.
//!
//! Implements 24-word (256-bit entropy) recovery phrase generation and validation.

use crate::types::RecoveryKey;
use bip39::{Language, Mnemonic};

/// Generate a 24-word BIP-39 recovery phrase (256-bit entropy)
///
/// # Design
/// - 24 words = 256 bits of entropy
/// - Language: English
/// - Entropy is random from OS CSPRNG
pub fn generate_recovery_phrase() -> Result<String, String> {
    // Generate with 256 bits of entropy (24 words)
    let mnemonic = Mnemonic::generate_in(Language::English, 24)
        .map_err(|e| format!("Failed to generate mnemonic: {}", e))?;

    // Collect words into space-separated string
    let words: Vec<&str> = mnemonic.words().collect();
    Ok(words.join(" "))
}

/// Validate and convert a recovery phrase to RecoveryKey
///
/// # Design
/// - Validates BIP-39 checksum
/// - Extracts 32 bytes of entropy
/// - Derives RecoveryKey via HKDF (in kdf module)
pub fn phrase_to_recovery_key(phrase: &str) -> Result<RecoveryKey, String> {
    // Parse and validate the mnemonic
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| format!("Invalid phrase: {}", e))?;

    // Extract entropy (32 bytes for 24-word phrase)
    let entropy = mnemonic.to_entropy();
    if entropy.len() != 32 {
        return Err(format!(
            "Expected 32 bytes of entropy for 24-word phrase, got {}",
            entropy.len()
        ));
    }

    let mut entropy_array = [0u8; 32];
    entropy_array.copy_from_slice(&entropy);

    // Derive RecoveryKey using HKDF
    crate::crypto::kdf::derive_recovery_key(&entropy_array)
}

/// Validate a recovery phrase (checksum and word count)
pub fn validate_recovery_phrase(phrase: &str) -> Result<(), String> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| format!("Invalid phrase: {}", e))?;

    let word_count = mnemonic.word_count();
    if word_count != 24 {
        return Err(format!("Expected 24-word phrase, got {} words", word_count));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_recovery_phrase() {
        let phrase = generate_recovery_phrase().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24, "Should generate 24 words");

        // Should validate correctly
        assert!(validate_recovery_phrase(&phrase).is_ok());

        // Two generated phrases should be different
        let phrase2 = generate_recovery_phrase().unwrap();
        assert_ne!(phrase, phrase2);
    }

    #[test]
    fn test_validate_recovery_phrase() {
        // Valid 24-word phrase (BIP-39 example)
        let valid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        assert!(validate_recovery_phrase(valid_phrase).is_ok());

        // Invalid: wrong word count
        let invalid_phrase = "abandon abandon abandon";
        assert!(validate_recovery_phrase(invalid_phrase).is_err());

        // Invalid: not a BIP-39 word
        let invalid_phrase = "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(validate_recovery_phrase(invalid_phrase).is_err());

        // Invalid: checksum failure (changed last word)
        let invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ability";
        assert!(validate_recovery_phrase(invalid_phrase).is_err());
    }

    #[test]
    fn test_phrase_to_recovery_key() {
        // Valid 24-word phrase
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let rk = phrase_to_recovery_key(phrase).unwrap();
        assert_eq!(rk.expose_secret().len(), 32);

        // Same phrase should produce same key
        let rk2 = phrase_to_recovery_key(phrase).unwrap();
        assert_eq!(rk.expose_secret(), rk2.expose_secret());

        // Different phrase should produce different key
        let phrase2 = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
        let rk3 = phrase_to_recovery_key(phrase2).unwrap();
        assert_ne!(rk.expose_secret(), rk3.expose_secret());
    }

    // BIP-39 official test vector
    // https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
    #[test]
    fn test_bip39_official_vector() {
        // Test vector from BIP-39 spec
        // Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        // Entropy (hex): 00000000000000000000000000000000

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::parse_in(Language::English, phrase).unwrap();
        let entropy = mnemonic.to_entropy();

        // This is a 12-word phrase (128-bit entropy), not our 24-word requirement
        assert_eq!(entropy.len(), 16);
        assert_eq!(entropy, vec![0u8; 16]);

        // Test a 24-word phrase
        let phrase_24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic_24 = Mnemonic::parse_in(Language::English, phrase_24).unwrap();
        let entropy_24 = mnemonic_24.to_entropy();

        // 24 words = 256 bits = 32 bytes
        assert_eq!(entropy_24.len(), 32);
        assert_eq!(entropy_24, vec![0u8; 32]);
    }

    #[test]
    fn test_round_trip() {
        // Generate a phrase
        let phrase = generate_recovery_phrase().unwrap();

        // Convert to recovery key
        let rk1 = phrase_to_recovery_key(&phrase).unwrap();

        // Convert again - should get same key
        let rk2 = phrase_to_recovery_key(&phrase).unwrap();

        assert_eq!(rk1.expose_secret(), rk2.expose_secret());
    }
}
