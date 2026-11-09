use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MAX_PLAINTEXT: usize = 64 * 1024 * 1024;
const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const LANES: u32 = 4;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealRecord {
    pub version: u32,
    pub algorithm: String,
    pub kdf: String,
    pub salt: String,
    pub nonce: String,
    pub blob_sha256: String,
    pub key_id: String,
    pub provider: String,
    pub sealed_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealRequest {
    pub operation: String,
    pub password: String,
    #[serde(default)]
    pub plaintext_b64: Option<String>,
    #[serde(default)]
    pub blob_b64: Option<String>,
    #[serde(default)]
    pub record: Option<SealRecord>,
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub associated_data_b64: Option<String>,
}
fn default_provider() -> String { "Local".into() }

#[derive(Debug, Serialize)]
pub struct SealResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<SealRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    if password.is_empty() || password.len() > 4096 { return Err("invalid_password_length".into()); }
    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(KEY_LEN))
        .map_err(|_| "invalid_kdf_parameters")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| "key_derivation_failed")?;
    Ok(key)
}

pub fn seal(plaintext: &[u8], password: &str, provider: &str, aad: &[u8]) -> Result<(Vec<u8>, SealRecord), String> {
    if provider != "Local" { return Err("unsupported_provider".into()); }
    if plaintext.len() > MAX_PLAINTEXT { return Err("plaintext_too_large".into()); }
    let mut salt = [0u8; SALT_LEN]; let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt); OsRng.fill_bytes(&mut nonce);
    let mut key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "cipher_init_failed")?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| "encryption_failed")?;
    key.zeroize();
    let digest = hex::encode(Sha256::digest(&ciphertext));
    let record = SealRecord {
        version: 1, algorithm: "AES-256-GCM".into(), kdf: "Argon2id-v1.3-m65536-t3-p4".into(),
        salt: STANDARD.encode(salt), nonce: STANDARD.encode(nonce), blob_sha256: digest,
        key_id: "password-derived-v1".into(), provider: provider.into(),
        sealed_at: "caller-supplied-or-omitted".into(),
    };
    Ok((ciphertext, record))
}

pub fn open(blob: &[u8], password: &str, record: &SealRecord, aad: &[u8]) -> Result<Vec<u8>, String> {
    if record.version != 1 || record.algorithm != "AES-256-GCM" ||
       record.kdf != "Argon2id-v1.3-m65536-t3-p1" || record.provider != "Local" {
        return Err("unsupported_or_invalid_record".into());
    }
    if hex::encode(Sha256::digest(blob)) != record.blob_sha256 { return Err("integrity_failure".into()); }
    let salt = STANDARD.decode(&record.salt).map_err(|_| "invalid_salt")?;
    let nonce = STANDARD.decode(&record.nonce).map_err(|_| "invalid_nonce")?;
    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN || blob.len() < TAG_LEN {
        return Err("invalid_blob_or_parameters".into());
    }
    let mut key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "cipher_init_failed")?;
    let result = cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: blob, aad })
        .map_err(|_| "authentication_failed".to_string());
    key.zeroize();
    result
}

pub fn handle(request: SealRequest) -> SealResponse {
    let aad = match request.associated_data_b64.as_deref() {
        Some(v) => match STANDARD.decode(v) { Ok(x) => x, Err(_) => return fail("invalid_associated_data") },
        None => Vec::new()
    };
    match request.operation.as_str() {
        "seal" => {
            let plain = match request.plaintext_b64.as_deref().map(|v| STANDARD.decode(v)).transpose() {
                Ok(Some(v)) => v, _ => return fail("invalid_plaintext_b64")
            };
            match seal(&plain, &request.password, &request.provider, &aad) {
                Ok((blob, record)) => SealResponse { status:"success".into(), blob_b64:Some(STANDARD.encode(blob)), plaintext_b64:None, record:Some(record), error:None },
                Err(e) => fail(&e)
            }
        },
        "open" => {
            let blob = match request.blob_b64.as_deref().map(|v| STANDARD.decode(v)).transpose() {
                Ok(Some(v)) => v, _ => return fail("invalid_blob_b64")
            };
            let record = match request.record { Some(r) => r, None => return fail("missing_record") };
            match open(&blob, &request.password, &record, &aad) {
                Ok(plain) => SealResponse { status:"success".into(), blob_b64:None, plaintext_b64:Some(STANDARD.encode(plain)), record:None, error:None },
                Err(e) => fail(&e)
            }
        },
        _ => fail("unsupported_operation")
    }
}
fn fail(error: &str) -> SealResponse {
    SealResponse { status:"error".into(), blob_b64:None, plaintext_b64:None, record:None, error:Some(error.into()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_and_tamper_detection() {
        let (blob, record) = seal(b"portable secret", "correct horse battery staple", "Local", b"ctx").unwrap();
        assert_eq!(open(&blob, "correct horse battery staple", &record, b"ctx").unwrap(), b"portable secret");
        let mut altered = blob.clone(); altered[0] ^= 1;
        assert_eq!(open(&altered, "correct horse battery staple", &record, b"ctx").unwrap_err(), "integrity_failure");
    }
    #[test]
    fn rejects_non_local_provider() {
        assert_eq!(seal(b"x", "password", "Google", b"").unwrap_err(), "unsupported_provider");
    }
    #[test]
    fn aad_is_authenticated() {
        let (blob, record) = seal(b"x", "password", "Local", b"one").unwrap();
        assert_eq!(open(&blob, "password", &record, b"two").unwrap_err(), "authentication_failed");
    }
}
