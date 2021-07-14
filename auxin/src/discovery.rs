use std::{collections::HashMap, io::Read};
use libsignal_protocol::{HKDF, PublicKey};
use serde::{Serialize, Deserialize};
use crate::Result;

///Magic string referring to the Intel SGX enclave ID used by Signal.
pub const ENCLAVE_ID: &str = "c98e00a4e3ff977a56afefe7362a27e4961e4f19e211febfbb19b897e6b80b15";

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryRequestEnvelope {
    pub request_id: Vec<u8>,
    pub iv: [u8; 12],
    pub data: Vec<u8>,
    pub mac: [u8; 16],
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryRequest {
    pub address_count: usize,
    pub commitment: [u8; 32],
    pub iv: [u8; 12],
    pub data: Vec<u8>,
    pub mac: [u8; 16],
    /// There must be between 1 and 3 envelopes.
    pub envelopes: HashMap<String, DiscoveryRequestEnvelope>,
}

/// The response body from GET https://textsecure-service.whispersystems.org/v1/directory/auth
/// when we attempt to upgrade our auth username & password
/// When we end up using this, we will base64-encode "$username:$password" and use that as
/// the authorization code for discovery requests.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DirectoryAuthResponse {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationRequest {
    /// Base64-encoded EC public key.
    pub client_public : String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationSignatureBody { 
    pub id: String,
    pub timestamp: String,
    pub version: usize,
    pub isv_enclave_quote_status: String,
    pub isv_enclave_quote_body: String,
}

/// (inner) response to a PUT request to https://api.directory.signal.org/v1/attestation/{ENCLAVE_ID}
/// Will always arrive inside a AttestationResponseList. 
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
    pub server_ephemeral_public: String,
    pub server_static_public: String,
    pub quote: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
    pub signature: String,
    pub certificates: String,
    pub signature_body: AttestationSignatureBody,
}

/// Response to a PUT request to https://api.directory.signal.org/v1/attestation/{ENCLAVE_ID}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AttestationResponseList { 
    pub attestations: HashMap<String, AttestationResponse>,
}

/// Returns client_key and server_key
pub fn make_remote_attestation_keys(local_keys : &libsignal_protocol::KeyPair, server_ephemeral_pk_bytes: &[u8; 32], server_static_pk_bytes: &[u8; 32]) -> Result<(PublicKey, PublicKey)> {
    
    let server_ephemeral_pk = PublicKey::from_djb_public_key_bytes(server_ephemeral_pk_bytes)?;

    let server_static_pk = PublicKey::from_djb_public_key_bytes(server_ephemeral_pk_bytes)?;
    
    let ephemeral_to_ephemeral = local_keys.calculate_agreement(&server_ephemeral_pk)?;
    let ephemeral_to_static = local_keys.calculate_agreement(&server_static_pk)?;

    let mut master_secret: [u8; 64] = [0;64];
    master_secret[0..32].copy_from_slice(&ephemeral_to_ephemeral);
    master_secret[32..64].copy_from_slice(&ephemeral_to_static);

    let mut public_keys_salt: [u8; 96] = [0;96];
    public_keys_salt[0..32].copy_from_slice(&local_keys.public_key.public_key_bytes()?);
    public_keys_salt[32..64].copy_from_slice(server_ephemeral_pk_bytes);
    public_keys_salt[64..96].copy_from_slice(server_static_pk_bytes);

    // TODO: Double-check if we need to propagate message_version from the server somewhere to here.
    let generator = HKDF::new(3)?;
    let keys = generator.derive_salted_secrets(&master_secret, &public_keys_salt, &([] as [u8;0]), 64)?;

    // Split "keys" into an agreed client key and  an agreed server key. 
    // "keys" should always have length 64, or else it'll panic here. 
    let mut client_key: [u8; 32] = [0; 32];
    client_key.copy_from_slice(&keys[0..32]);
    let mut server_key: [u8; 32] = [0; 32];
    server_key.copy_from_slice(&keys[32..64]);

    Ok( ( PublicKey::from_djb_public_key_bytes(&client_key)?, PublicKey::from_djb_public_key_bytes(&server_key)? ) )
  }
