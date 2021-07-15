use std::{collections::HashMap, convert::TryFrom};
use libsignal_protocol::{HKDF, PublicKey};
use log::{debug, warn};
use serde::{Serialize, Deserialize};
use crate::{IAS_TRUST_ANCHOR, Result};
use x509_certificate::{CapturedX509Certificate};

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
/// Will always arrive inside an AttestationResponseList. 
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
    pub server_ephemeral_public: String,
    pub server_static_public: String,
    pub quote: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
    /// Equivalent to an X-IAS-Report-Signature, but sent inline with the json body. 
    pub signature: String,
    /// Appears to be equivalent to X-IASReport-Signing-Certificate
    pub certificates: String,
    // A Json string equivalent to AttestationSignatureBody above.
    pub signature_body: String,
}

impl AttestationResponse {
    pub fn verify(&self) -> Result<()> {
        self.verify_signature() //.and(self.verify_quote())
    }

    pub fn verify_signature(&self) -> Result<()> { 
        // ----- Decode/construct our trust anchor.
        //SHOULD only contain one entity, DER- encoded.
        //let anchor = webpki::TrustAnchor::try_from_cert_der(IAS_TRUST_ANCHOR)?;
        let anchor_x509 = CapturedX509Certificate::from_der(IAS_TRUST_ANCHOR)?;

        //Confirm our anchor is self-signing.
        anchor_x509.verify_signed_by_certificate(&anchor_x509)?;

        let trust_anchors = vec!(anchor_x509.clone());

        // ----- Decode and validate our certificate chain.

        //let response_certs: Vec<&str> = self.certificates.split_inclusive("-----END CERTIFICATE-----\n").collect();
        let response_certs = CapturedX509Certificate::from_pem_multiple(&self.certificates)?;
        //For every cert which the server sent us which is *not* the trust anchor, generate a chain.
        let mut chains: Vec<Vec<&CapturedX509Certificate>> = Vec::default();
        for cert in response_certs.iter() {
            // The server sends us a copy of the trust anchor.
            // Lucky for us, the anchor should be self-signing,
            // so verifying validity should be very easy: 
            if cert.serial_number_asn1() == anchor_x509.serial_number_asn1() {
                cert.verify_signed_by_certificate(&anchor_x509)?;
            }
            else {
                let mut chain = cert.resolve_signing_chain(response_certs.iter().chain( trust_anchors.iter() ) );
                chain.insert(0, cert);
                chains.push(chain);
            }
        }
        
        // TODO: so far, the server hasn't sent more or less than one chain / non-trust-root cert. However, we should be set up to handle that gracefully.
        if chains.len() > 1 {
            warn!("More than one certificate chain has been provided. Defaulting to first valid chain.");
        }
        let chain = chains.get_mut(0).unwrap();
        chain.dedup();
        // This thing needs to end in our trust anchor, or something signed by our trust anchor.
        chain.last().unwrap().verify_signed_by_certificate(anchor_x509)?;
        debug!("Confirmed that the provided certificate chain is valid!");

        // ----- Verify signature on response.
        let cert = *chain.first().unwrap();
        //Figure out a verification algorithm, which requires both a key algorithm and a signature algorithm.
        let key_algorithm = x509_certificate::KeyAlgorithm::try_from(cert.key_algorithm().unwrap())?;
        let signature_algorithm = x509_certificate::SignatureAlgorithm::try_from(cert.signature_algorithm().unwrap())?;
        let verify_algorithm = signature_algorithm.resolve_verification_algorithm(key_algorithm)?;
        
        let cipher = ring::signature::UnparsedPublicKey::new(verify_algorithm, cert.public_key_data());

        let sig: Vec<u8> = base64::decode(&self.signature)?;
        debug!("Signature received on attestation is {} bytes", sig.len());

        cipher.verify(self.signature_body.as_bytes(), sig.as_slice())?;

        Ok(())
    }

    // TODO TODO TODO HIGH PRIORITY: Verify the "Quote" !
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
