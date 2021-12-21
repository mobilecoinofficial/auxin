// Copyright (c) 2021 MobileCoin Inc.
// Copyright (c) 2021 Emily Cultip

use crate::LocalIdentity;
use libsignal_protocol::IdentityKeyPair;
use log::debug;
use protobuf::{CodedOutputStream, Message};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
	profile_cipher::*,
	utils::{serde_base64, serde_optional_base64},
};

use zkgroup::profiles::ProfileKeyVersion;

/// Information on which capabilities this peer has, as sent to us from Signal's web API.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfileCapabilitiesResponse {
	pub gv2: bool,
	#[serde(rename = "senderKey")]
	pub sender_key: bool,
	#[serde(rename = "announcementGroup")]
	pub announcement_group: bool,
	#[serde(rename = "gv1-migration")]
	pub gv1_migration: bool,
}

/// A response from Signal's Web API containing profile information pertaining to a user.
/// NOTE FOR FURTHER DEVELOPMENT: Appears to be identical to ForeignPeerProfile!
/// It might be worth looking into ways to deduplicate / merge those code paths.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProfileResponse {
	/// Base-64
	pub identity_key: String,
	/// Base-64
	pub name: Option<String>,
	/// Base-64
	pub about: Option<String>,
	/// Base-64
	pub about_emoji: Option<String>,
	/// Follows the form of "profiles/{Base-64 string}
	pub avatar: Option<String>,
	/// Base-64 encoded signalservice.proto:PaymentAddress
	pub payment_address: Option<String>,
	/// Base-64
	pub unidentified_access: Option<String>,
	pub unrestricted_unidentified_access: bool,
	pub capabilities: ProfileCapabilitiesResponse,
	/// As of yet unused, at least as far as I can see.
	pub username: Option<String>,
	pub uuid: Option<Uuid>,
	/// "Credential key," base-64 encoded.
	pub credential: Option<String>,
}

/// Parameters for a Signal user profile, plaintext, as provided by the user.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProfileConfig {
	pub about: Option<String>,
	/// A MobileCoin public address to be applied to the profile. Note that this address is base64-encoded,
	/// not put in MobileCoin's custom base58 encoding standard - it may be worth checking which encoding
	/// your MobileCoin wallet implementation (e.g. full-service) uses, to ensure you are re-encoding
	/// this structure if it is necessary to do so.
	pub mobilecoin_address: Option<String>,
	pub mood_emoji: Option<String>,
	pub name: ProfileName<String>,
	pub avatar_file: Option<String>,
}

/// Parameters for a Signal user profile.
/// Ciphertext - to be generatd by build_set_profile_request() and sent to Signal's web API. Plaintext will not work in any of these fields.
/// When serialized to json this is the format that a PUT request to "/v1/profile/%s" is expected to have.
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSetRequest {
	/// Hex-encoded
	version: String,
	#[serde(with = "serde_base64")]
	name: Vec<u8>,
	#[serde(with = "serde_base64")]
	about: Vec<u8>,
	#[serde(with = "serde_base64")]
	about_emoji: Vec<u8>,
	#[serde(with = "serde_optional_base64")]
	payment_address: Option<Vec<u8>>,
	/// Avatar is a boolean here because, if avatar is True, we get a PreUploadToken for an avatar here.
	/// Due to the way I/O responsibility is supposed to live outside of Auxin and in something like
	/// auxin_cli, avatar uploading cannot be fully handled inline with build_set_profile_request()
	avatar: bool,
	#[serde(with = "serde_base64")]
	commitment: Vec<u8>,
}

/// Prepare a ProfileSetRequest from the given arguments. This struct can be serialized to json and sent in the body of
/// a PUT request to "/v1/profile/%s" to modify your profile.
#[allow(dead_code)]
pub fn build_set_profile_request<R: CryptoRng + Rng>(
	parameters: ProfileConfig,
	identity: &LocalIdentity,
	rng: &mut R,
) -> crate::Result<ProfileSetRequest> {
	let uuid = identity.address.get_uuid().unwrap();
	let profile_key = zkgroup::profiles::ProfileKey::create(identity.profile_key.clone());

	// Profile encryption
	let profile_cipher = ProfileCipher::from(profile_key);

	let name = profile_cipher.encrypt_name(parameters.name.as_ref())?;
	let about = parameters.about.unwrap_or_default();
	let about_emoji = parameters.mood_emoji.unwrap_or_default();

	let about = profile_cipher.encrypt_about(about)?;
	let about_emoji = profile_cipher.encrypt_emoji(about_emoji)?;

	// Payment address encrpytion.
	let payment_address: Option<Vec<u8>> = match &parameters.mobilecoin_address {
		Some(b64_addr) => {
			// Decode our mobilecoin public address.
			let plaintext = base64::decode(b64_addr)?;
			// Sign it, getting a Signal protocol payment address.
			let address = sign_payment_address(&plaintext, &identity.identity_keys, rng)?;
			// Turn a protobuf into a regular byte buffer.
			let mut serialized_address: Vec<u8> = Vec::default();
			let mut outstream = CodedOutputStream::vec(&mut serialized_address);
			let sz = address.compute_size();
			debug!("About to write {} -byte payment address", sz);
			protobuf::Message::write_to_with_cached_sizes(&address, &mut outstream)?;
			outstream.flush()?;
			drop(outstream);
			// Encrypt, attempting to pad to PAYMENTS_ADDRESS_CONTENT_SIZE
			let ciphertext = profile_cipher.pad_and_encrypt_with_length(
				&serialized_address,
				&[crate::profile_cipher::PAYMENTS_ADDRESS_CONTENT_SIZE],
			)?;
			Some(ciphertext)
		}
		None => None,
	};

	// Basic keys / cryptographic identity
	// Drop the cipher's ownership of the profile key, getting the profile key copy back.
	let profile_key = profile_cipher.into_inner();
	let profile_key_ver = get_profile_key_version(&profile_key, uuid);
	let commitment = profile_key.get_commitment(uuid.as_bytes().clone());

	// Per libsignal-service-rs' push_service.rs, bincode is transparent and this will return a hex-encoded string.
	let version = bincode::serialize(&profile_key_ver)?;
	let version = std::str::from_utf8(&version).expect("profile_key_version is hex encoded string");
	let commitment = bincode::serialize(&commitment)?;

	Ok(ProfileSetRequest {
		version: version.to_string(),
		name,
		about,
		about_emoji,
		payment_address,
		avatar: parameters.avatar_file.is_some(),
		commitment,
	})
}

/// Prepare a MobileCoin public address to be sent to Signal's web API so that we can set the payment address field on an account's profile.
pub fn sign_payment_address<R: CryptoRng + Rng>(
	mobilecoin_public_address: &[u8],
	keys: &IdentityKeyPair,
	rng: &mut R,
) -> crate::Result<auxin_protos::PaymentAddress> {
	let signature = keys
		.private_key()
		.calculate_signature(mobilecoin_public_address, rng)?;

	// Sgnature is supposed to be 64 bytes in length
	assert_eq!(signature.len(), 64);

	let mut mobilecoin_addr = auxin_protos::PaymentAddress_MobileCoinAddress::default();
	mobilecoin_addr.set_signature(signature.to_vec());
	mobilecoin_addr.set_address(mobilecoin_public_address.to_vec());
	let mut pay_addr = auxin_protos::PaymentAddress::default();

	pay_addr.set_mobileCoinAddress(mobilecoin_addr);

	Ok(pay_addr)
}

pub fn get_profile_key_version(
	profile_key: &zkgroup::profiles::ProfileKey,
	uuid: &Uuid,
) -> ProfileKeyVersion {
	let uid_bytes = uuid.as_bytes();
	profile_key.get_profile_key_version(uid_bytes.clone())
}
