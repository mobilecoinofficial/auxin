use crate::{
	address::{phone_number_to_long, E164},
	Result, IAS_TRUST_ANCHOR,
};
use aes_gcm::{
	aead::Payload,
	aead::{Aead, NewAead},
	Aes256Gcm, Nonce,
};
use libsignal_protocol::{PublicKey, HKDF};
use log::{debug, warn};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom};
use x509_certificate::CapturedX509Certificate;

///Magic string referring to the Intel SGX enclave ID used by Signal.
pub const ENCLAVE_ID: &str = "c98e00a4e3ff977a56afefe7362a27e4961e4f19e211febfbb19b897e6b80b15";

/// The response body from GET https://textsecure-service.whispersystems.org/v1/directory/auth
/// when we attempt to upgrade our auth username & password
/// When we end up using this, we will base64-encode "$username:$password" and use that as
/// the authorization code for discovery requests.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DirectoryAuthResponse {
	pub username: String,
	pub password: String,
}

/// A request used to initiate the Discovery process, used to retrieve an attestation. 
/// An attestation is part of the handshake process for interacting with a remote
/// Intel SGX Enclave, in this case Signal's contact-discovery SGX Enclave.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationRequest {
	/// Base64-encoded EC public key.
	pub client_public: String,
}

/// The signature sent as a response to our attestation request, signing the attestation.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationSignatureBody {
	pub id: String,
	pub timestamp: String,
	pub version: usize,
	pub isv_enclave_quote_status: String,
	pub isv_enclave_quote_body: String,
}

pub type AttestationRequestId = Vec<u8>;

/// A response to a PUT request to https://api.directory.signal.org/v1/attestation/{ENCLAVE_ID}
/// Will always arrive inside an AttestationResponseList.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
	/// Base-64 encoding of a [u8; 32]
	pub server_ephemeral_public: String,
	/// Base-64 encoding of a [u8; 32]
	pub server_static_public: String,
	pub quote: String,
	/// Initialization vector. Base-64 encoding of a [u8; 12]
	pub iv: String,
	pub ciphertext: String,
	/// Tag - to be appended to the ciphertext before decryption. Notably NOT an aad. Base-64 encoding of a [u8; 16]
	pub tag: String,
	/// Equivalent to an X-IAS-Report-Signature, but sent inline with the json body.
	pub signature: String,
	/// Appears to be equivalent to X-IASReport-Signing-Certificate
	pub certificates: String,
	// A Json string equivalent to AttestationSignatureBody above.
	pub signature_body: String,
}

impl AttestationResponse {
	/// Verify that this attestation is valid.
	pub fn verify(&self) -> Result<()> {
		self.verify_signature() //.and(self.verify_quote())
	}

	/// Verify that this attestation's signature is valid.
	pub fn verify_signature(&self) -> Result<()> {
		// ----- Decode/construct our trust anchor.
		//SHOULD only contain one entity, DER- encoded.
		//let anchor = webpki::TrustAnchor::try_from_cert_der(IAS_TRUST_ANCHOR)?;
		let anchor_x509 = CapturedX509Certificate::from_der(IAS_TRUST_ANCHOR)?;

		//Confirm our anchor is self-signing.
		anchor_x509.verify_signed_by_certificate(&anchor_x509)?;

		let trust_anchors = vec![anchor_x509.clone()];

		// ----- Decode and validate our certificate chain.

		let response_certs = CapturedX509Certificate::from_pem_multiple(&self.certificates)?;
		//For every cert which the server sent us which is *not* the trust anchor, generate a chain.
		let mut chains: Vec<Vec<&CapturedX509Certificate>> = Vec::default();
		for cert in response_certs.iter() {
			// The server sends us a copy of the trust anchor.
			// Lucky for us, the anchor should be self-signing,
			// so verifying validity should be very easy:
			if cert.serial_number_asn1() == anchor_x509.serial_number_asn1() {
				cert.verify_signed_by_certificate(&anchor_x509)?;
			} else {
				let mut chain =
					cert.resolve_signing_chain(response_certs.iter().chain(trust_anchors.iter()));
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
		chain
			.last()
			.unwrap()
			.verify_signed_by_certificate(anchor_x509)?;
		debug!("Confirmed that the provided certificate chain is valid!");

		// ----- Verify signature on response.
		let cert = *chain.first().unwrap();
		//Figure out a verification algorithm, which requires both a key algorithm and a signature algorithm.
		let key_algorithm =
			x509_certificate::KeyAlgorithm::try_from(cert.key_algorithm().unwrap())?;
		let signature_algorithm =
			x509_certificate::SignatureAlgorithm::try_from(cert.signature_algorithm().unwrap())?;
		let verify_algorithm = signature_algorithm.resolve_verification_algorithm(key_algorithm)?;

		let cipher =
			ring::signature::UnparsedPublicKey::new(verify_algorithm, cert.public_key_data());

		let sig: Vec<u8> = base64::decode(&self.signature)?;
		debug!("Signature received on attestation is {} bytes", sig.len());

		cipher.verify(self.signature_body.as_bytes(), sig.as_slice())?;

		debug!("Successfully verified attestation signature.");

		Ok(())
	}

	/// Decodes an AttestationRequestID from this AttestationResponse
	/// 
	/// # Arguments
	/// 
	/// * `our_ephemeral_keys` - The ephemeral key-pair generated specifically for this attestation / discovery process.
	pub fn decode_request_id(
		&self,
		our_ephemeral_keys: &libsignal_protocol::KeyPair,
	) -> Result<AttestationRequestId> {
		self.decode_request_id_with_keys(&self.make_remote_attestation_keys(our_ephemeral_keys)?)
	}


	/// Decodes an AttestationRequestID from this AttestationResponse
	/// 
	/// # Arguments
	/// 
	/// * `keys` - Attestation keys, generated from our user account's identity keys as well as the server's ephemeral public key and the server's static public key,
	pub fn decode_request_id_with_keys(
		&self,
		keys: &AttestationKeys,
	) -> Result<AttestationRequestId> {
		let server_key = aes_gcm::Key::from_slice(&keys.server_key);
		let cipher = Aes256Gcm::new(server_key);
		let mut ciphertext_bytes = base64::decode(&self.ciphertext)?;
		let tag_bytes = base64::decode(&self.tag)?;
		assert_eq!(tag_bytes.len(), 16);
		//IV corresponds to nonce here.
		let iv_bytes = base64::decode(&self.iv)?;
		assert_eq!(iv_bytes.len(), 12);
		let nonce = Nonce::from_slice(iv_bytes.as_slice());

		//When developing this, I thought "tag" referred to "aad". NOPE! Tag gets appended to the ciphertext. We have no aad.
		ciphertext_bytes.extend(tag_bytes.iter());
		let payload = Payload {
			msg: &ciphertext_bytes,
			aad: b"",
		};

		Ok(cipher.decrypt(nonce, payload)?)
	}

	/// Decodes and generates a set of attestation keys from this response and from our local set of ephemeral keys.
	/// 
	/// # Arguments
	/// 
	/// * `our_ephemeral_keys` - Temporary keys we generated for this attestation / discovery process.
	pub fn make_remote_attestation_keys(
		&self,
		our_ephemeral_keys: &libsignal_protocol::KeyPair,
	) -> Result<AttestationKeys> {
		//TODO: Observe DRY here. Maybe a special Serde visitor for fixed-length arrays.
		let server_static_vec: Vec<u8> = base64::decode(&self.server_static_public)?;
		assert_eq!(server_static_vec.len(), 32);
		let mut server_static: [u8; 32] = [0; 32];
		server_static.copy_from_slice(&server_static_vec.as_slice()[0..32]);

		let server_ephemeral_vec: Vec<u8> = base64::decode(&self.server_ephemeral_public)?;
		assert_eq!(server_ephemeral_vec.len(), 32);
		let mut server_ephemeral: [u8; 32] = [0; 32];
		server_ephemeral.copy_from_slice(&server_ephemeral_vec.as_slice()[0..32]);

		gen_remote_attestation_keys(our_ephemeral_keys, &server_ephemeral, &server_static)
	}
}

/// Response to a PUT request to https://api.directory.signal.org/v1/attestation/{ENCLAVE_ID}
/// Contains a list of attestations, mapping an attestation ID to an attestation response. 
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AttestationResponseList {
	pub attestations: HashMap<String, AttestationResponse>,
}

impl AttestationResponseList {
	/// Verify all attestations in this list, ensuring all of them are valid. 
	pub fn verify_attestations(&self) -> Result<()> {
		for (_, a) in self.attestations.iter() {
			a.verify()?;
		}
		return Ok(());
	}

	/// Decodes request IDs and also generates attestation keys for each attestation we have received.
	/// Also returns the serial number of each attestation, for convenience.
	/// Requires the temporary keys we made our attestation request with to decode this.
	/// 
	/// # Arguments
	/// 
	/// * `local_keys` - Our local node's ephemeral keys - must match the ones used to request this attestation list earlier.
	pub fn decode_attestations(
		&self,
		local_keys: &libsignal_protocol::KeyPair,
	) -> Result<Vec<(String, AttestationKeys, AttestationRequestId)>> {
		let mut result = Vec::default();
		for (aid, attest) in self.attestations.iter() {
			let keys = attest.make_remote_attestation_keys(local_keys)?;
			let req = attest.decode_request_id_with_keys(&keys)?;
			result.push((aid.clone(), keys, req));
		}
		return Ok(result);
	}
}

/// For use decrypting attestation responses.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Copy)]
pub struct AttestationKeys {
	pub client_key: [u8; 32],
	pub server_key: [u8; 32],
}

/// Gnerates a set of attestation keys from the server's ephemeral key and static key from an AttestationResponse,
/// and from our local set of ephemeral keys.
/// Returns client_key and server_key, wrapped up in a AttestationKeys.
/// 
/// # Arguments
/// 
/// * `local_keys` - Our local ephemeral keypair, temporary keys we generated for this attestation / discovery process.
/// * `server_ephemeral_pk_bytes` - The ephemeral key the server sent us as part of an AttestationResponse.
/// * `server_static_pk_bytes` - The static key the server sent us as part of an AttestationResponse.
pub fn gen_remote_attestation_keys(
	local_keys: &libsignal_protocol::KeyPair,
	server_ephemeral_pk_bytes: &[u8; 32],
	server_static_pk_bytes: &[u8; 32],
) -> Result<AttestationKeys> {
	let server_ephemeral_pk = PublicKey::from_djb_public_key_bytes(server_ephemeral_pk_bytes)?;
	let server_static_pk = PublicKey::from_djb_public_key_bytes(server_static_pk_bytes)?;

	let ephemeral_to_ephemeral = local_keys.calculate_agreement(&server_ephemeral_pk)?;
	let ephemeral_to_static = local_keys.calculate_agreement(&server_static_pk)?;

	let mut master_secret: [u8; 64] = [0; 64];
	master_secret[0..32].copy_from_slice(&ephemeral_to_ephemeral);
	master_secret[32..64].copy_from_slice(&ephemeral_to_static);

	let mut public_keys_salt: [u8; 96] = [0; 96];
	public_keys_salt[0..32].copy_from_slice(&local_keys.public_key.public_key_bytes()?);
	public_keys_salt[32..64].copy_from_slice(server_ephemeral_pk_bytes);
	public_keys_salt[64..96].copy_from_slice(server_static_pk_bytes);

	// TODO: Double-check if we need to propagate message_version from the server somewhere to here.
	let generator = HKDF::new(3)?;
	let keys =
		generator.derive_salted_secrets(&master_secret, &public_keys_salt, &([] as [u8; 0]), 64)?;

	// Split "keys" into an agreed client key and  an agreed server key.
	// "keys" should always have length 64, or else it'll panic here.
	let mut client_key: [u8; 32] = [0; 32];
	client_key.copy_from_slice(&keys[0..32]);
	let mut server_key: [u8; 32] = [0; 32];
	server_key.copy_from_slice(&keys[32..64]);

	Ok(AttestationKeys {
		client_key,
		server_key,
	})
}

//Every "String" field here is a base64-encoded byte vector.
/// An individual entry in a discovery query.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QueryEnvelope {
	pub request_id: String,
	// Initialization Vector
	pub iv: String,
	pub data: String,
	pub mac: String,
}

//Every "String" field here is a base64-encoded byte vector (except the key for the envelopes map)
/// A request for a discovery query, sent in to Signal's contact-discovery SGX enclave.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryRequest {
	/// The number of phone numbers we're sending in hopes of getting corresponding UUIDs for them.
	pub address_count: i64,
	pub commitment: String,
	// Initialization Vector
	pub iv: String,
	pub data: String,
	pub mac: String,

	/// There must be between 1 and 3 envelopes.
	pub envelopes: HashMap<String, QueryEnvelope>,

	#[serde(skip)]
	pub query_key: [u8; 32],
}

/// Build a query we will use to request UUIDs corresponding to phone numbers
/// 
/// # Arguments
/// 
/// * `phone_numbers` - A list of phone numbers we are seeking corresponding UUIDs for.
/// * `rand` - The cryptographically-strong source of entropy for this process.
pub fn build_query_data<R>(phone_numbers: &Vec<E164>, rand: &mut R) -> Result<Vec<u8>>
where
	R: RngCore + CryptoRng,
{
	let mut res: Vec<u8> = Vec::default();
	let nonce: [u8; 32] = rand.gen();
	//Write the nonce (TODO: Find a more graceful way to copy an entire array into a Vec.
	for b in nonce {
		res.push(b);
	}

	for addr in phone_numbers {
		let num = phone_number_to_long(addr)?;
		//The java function org.whispersystems.libsignal.util.ByteUtil::longToByteArray
		//appears to be taking a little-endian value and making it big-endian.
		let bytes = num.to_be_bytes();
		//AGAIN, todo: make this more elegant.
		for b in bytes {
			res.push(b);
		}
	}
	return Ok(res);
}

impl DiscoveryRequest {
	/// Create a discovery request. With the use of remote attestations, this should allow you to get a Signal user's UUID from their phone number.
	///
	/// # Arguments
	///
	/// * `phone_numbers` - Addresses to request UUIDs for from the server. Must be E164 format i.e. +12345678910
	/// * `attestations` - A list of decoded attestation responses. Probably generated with AttestationResponseList::decode_attestations().
	/// * `rand` - Randomness provider.
	pub fn new<R>(
		phone_numbers: &Vec<E164>,
		attestations: &Vec<(String, AttestationKeys, AttestationRequestId)>,
		rand: &mut R,
	) -> Result<Self>
	where
		R: RngCore + CryptoRng,
	{
		let mut envelopes: HashMap<String, QueryEnvelope> =
			HashMap::with_capacity(attestations.len());

		// Query key - used both in the envelopes and the request.
		let query_key: [u8; 32] = rand.gen();

		//Iterate attestations and build an "envelope" for each.
		for (attestation_id, keys, req) in attestations.iter() {
			//Inner cipher
			//Build cipher
			let envl_key = aes_gcm::Key::from_slice(&keys.client_key);
			let envl_cipher = Aes256Gcm::new(envl_key);
			// IMPORTANT NOTE - Request ID is the "AAD" here.
			// and the "plaintext to be enciphered is our query key (?)"
			let envl_payload = Payload {
				msg: &query_key,
				aad: req.as_slice(),
			};
			let envl_nonce_bytes: [u8; 12] = rand.gen();
			let envl_nonce = Nonce::from_slice(&envl_nonce_bytes);
			let envl_ciphertext = envl_cipher.encrypt(envl_nonce, envl_payload)?;

			//Assumes 16-byte tag
			let (envl_data, envl_tag) = envl_ciphertext.split_at(envl_ciphertext.len() - 16);

			let envl = QueryEnvelope {
				request_id: base64::encode(&req),
				iv: base64::encode(&envl_nonce_bytes),
				data: base64::encode(envl_data),
				mac: base64::encode(envl_tag),
			};
			envelopes.insert(attestation_id.clone(), envl);
		}

		// There must be between 1 and 3 envelopes.
		assert!((4 > envelopes.len()) && (envelopes.len() > 0)); //TODO: Better error handling here.

		//Generate the unencrypted binary request for contact discovery.
		let query_data = build_query_data(phone_numbers, rand)?;

		//Build cipher for request.
		let qk = aes_gcm::Key::from_slice(&query_key);
		let cipher = Aes256Gcm::new(qk);
		let payload = Payload {
			msg: &query_data,
			aad: b"",
		};
		let nonce_bytes: [u8; 12] = rand.gen();
		let nonce = Nonce::from_slice(&nonce_bytes);
		let ciphertext = cipher.encrypt(nonce, payload)?;

		//Hash the query plaintext.
		let commitment = ring::digest::digest(&ring::digest::SHA256, &query_data);
		let commitment = Vec::from(commitment.as_ref());

		//Assumes 16-byte tag
		let (data, tag) = ciphertext.split_at(ciphertext.len() - 16);

		Ok(Self {
			address_count: phone_numbers.len() as i64,
			commitment: base64::encode(&commitment),
			iv: base64::encode(&nonce_bytes),
			data: base64::encode(data),
			mac: base64::encode(tag),
			envelopes,
			query_key,
		})
	}
}

/// The response to a Signal Discovery Service request, sent out of their Intel SGX enclave.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryResponse {
	pub request_id: String,
	pub iv: String,
	pub data: String,
	pub mac: String,
}

impl DiscoveryResponse {
	/// Decrypt the discovery response.
	pub fn decrypt(
		&self,
		attestations: &Vec<(String, AttestationKeys, AttestationRequestId)>,
	) -> Result<Vec<u8>> {
		let our_request_id: Vec<u8> = base64::decode(self.request_id.clone())?;
		for (_name, keys, req_id) in attestations {
			debug!("Comparing incoming discovery response with request ID {:?} against attestation request ID {:?}", our_request_id, req_id);
			if &our_request_id == req_id {
				let key = aes_gcm::Key::from_slice(&keys.server_key);
				let iv_not_sized = base64::decode(self.iv.clone())?;
				let mut iv: [u8; 12] = [0; 12];
				iv.copy_from_slice(&iv_not_sized.as_slice()[0..12]);
				let mut ciphertext_bytes = base64::decode(self.data.clone())?;
				let tag_bytes = base64::decode(self.mac.clone())?;
				ciphertext_bytes.extend_from_slice(tag_bytes.as_slice());

				let nonce = Nonce::from_slice(&iv);
				let cipher = Aes256Gcm::new(key);
				let payload = Payload {
					msg: &ciphertext_bytes,
					aad: b"",
				};

				let decrypted = cipher.decrypt(nonce, payload)?;
				return Ok(decrypted);
			}
		}

		// TODO: ERROR HANDLING HERE.
		Ok(Vec::default())
	}
}
