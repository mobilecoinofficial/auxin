use std::collections::HashMap;
use serde::{Serialize, Deserialize};

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
struct AttestationRequest {
    /// Base64-encoded EC public key.
    pub client_public : String,
}