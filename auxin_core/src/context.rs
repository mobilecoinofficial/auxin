// Copyright (c) 2021 MobileCoin Inc.
// Copyright (c) 2021 Emily Cultip

use std::collections::HashMap;

use aes_gcm::{
	aead::{Aead, NewAead, Payload},
	Nonce,
};
use libsignal_protocol::{
	IdentityKeyPair, InMemIdentityKeyStore, InMemPreKeyStore, InMemSessionStore,
	InMemSignedPreKeyStore, SenderCertificate,
};
use log::debug;
use uuid::Uuid;

use crate::{
	address::*,
	groups::{
		group_storage::GroupInfo, sender_key::AuxinSenderKeyStore, GroupId,
		InMemoryCredentialsCache,
	},
	state::{PeerRecordStructure, PeerStore, UnidentifiedAccessMode},
};

pub const PROFILE_KEY_LEN: usize = 32;
pub type ProfileKey = [u8; PROFILE_KEY_LEN];

#[derive(Clone, Debug)]
pub struct AuxinConfig {
	pub enable_read_receipts: bool,
	/// How many milliseconds should a sender key distribution live before we create a new one automatically?
	pub sender_key_distribution_lifespan: u64,
}

impl Default for AuxinConfig {
	fn default() -> Self {
		Self {
			enable_read_receipts: true,
			sender_key_distribution_lifespan: 172800000, // 48 hours in milliseconds
		}
	}
}

/// Basic signal protocol information and key secrets for the local signal node.
/// This is not intended to be used to represent peers - instead, this is your user account,
/// the identity with which interacting with the Signal Protocol.
/// Primarily includes credentials and identifying information
#[derive(Clone)]
pub struct LocalIdentity {
	/// Our local phone number (or UUID, or both) as well as the device ID of this node.
	pub address: AuxinDeviceAddress,
	/// Signal user password.
	pub password: String,
	/// Our 32-byte (256-bit) Profile Key. Used extensively for sealed-sender messages.
	pub profile_key: ProfileKey,
	/// This node's public and private key.
	pub identity_keys: IdentityKeyPair,
	/// Registration ID.
	pub reg_id: u32,
}

impl LocalIdentity {
	/// Required HTTP header for our Signal requests.
	/// Authorization: "Basic {AUTH}""
	/// AUTH is a base64-encoding of: NUMBER:B64PWD, where NUMBER is our UUID and
	/// B64PWD is our base64-encoded password. It used to require NUMBER=E164 phone number but this has been changed.
	/// NOTE: Discovery requests will require a different user-ID and password, which is retrieved with a GET request to https://textsecure-service.whispersystems.org/v1/directory/auth
	pub fn make_auth_header(&self) -> String {
		let our_auth_value = format!(
			"{}.{}:{}",
			&self.address.address.get_uuid().unwrap().to_string(),
			self.address.device_id,
			&self.password
		);

		let b64_auth = base64::encode(our_auth_value);

		let mut our_auth = String::from("Basic ");
		our_auth.push_str(b64_auth.as_str());

		our_auth
	}

	/// Build a request for a "Sender Certificate," which is required in order to deliver "sealed sender" messages.
	pub fn build_sendercert_request<Body: Default>(&self) -> crate::Result<http::Request<Body>> {
		let req = crate::net::common_http_headers(
			http::Method::GET,
			"https://textsecure-service.whispersystems.org/v1/certificate/delivery",
			self.make_auth_header().as_str(),
		)?;
		Ok(req.body(Body::default())?)
	}
}

/// Wrapper type to force Rust to recognize libsignal ctx as "Send"
#[derive(Clone, Copy, Default)]
pub struct SignalCtx {
	pub(crate) ctx: libsignal_protocol::Context,
}

impl SignalCtx {
	pub fn get(&self) -> libsignal_protocol::Context {
		self.ctx
	}
}

// Dark magic! may cause crashes! completely unavoidable! Yay!
unsafe impl Send for SignalCtx {}

/// An AuxinContext holds all critical Signal protocol data.
/// It holds sessions, public keys of other users, and our public and private key, among other things.
/// This contains all of the keys and session state required to send and receive Signal messages.
#[allow(unused)] // TODO: Remove this after we can send/remove a message.
				 // This is the structure that an AuxinStateHandler builds and saves.
pub struct AuxinContext {
	/// The LocalIdentity holds this node's public and private key, its profile key,
	/// password, and its UUID and phone number.
	pub identity: LocalIdentity,

	/// A certificate used to send sealed-sender / unidentified-sender messages.
	/// Retrieved through a request to https://textsecure-service.whispersystems.org/v1/certificate/delivery
	pub sender_certificate: Option<SenderCertificate>,

	/// Records of peer session - their UUIDs, device IDs, preferences, etc.
	pub peer_cache: PeerRecordStructure,
	/// Signal Protocol in-memory session state. This holds Signal protocol sessions, which contain the ratchet key state and counter.
	pub session_store: InMemSessionStore,
	pub pre_key_store: InMemPreKeyStore,
	pub signed_pre_key_store: InMemSignedPreKeyStore,
	/// Stores public keys from peers.
	pub identity_store: InMemIdentityKeyStore,
	pub sender_key_store: AuxinSenderKeyStore,

	/// Configuration for the Auxin library.
	pub config: AuxinConfig,
	/// Should we show up as "Online" to other Signal users?
	pub report_as_online: bool,

	pub groups: HashMap<GroupId, GroupInfo>,
	pub credentials_manager: InMemoryCredentialsCache,

	/// Signal context - pointer to a C data type.
	///
	/// It seems like this is future-proofing on Signal's behalf, because
	/// the Signal's library never uses this datatype directly even though
	/// it is required as an argument to many of their methods.
	pub ctx: SignalCtx,
}

/// Generate an unidentified access key from a profile key.
/// Basically, performs a cryptographic operation on this profile key to generate another key,
/// which can be used to send and receive sealed-sender messages.
///
/// # Arguments
///
/// * `profile_key` - A base-64 string encoding of a signal user's 32-byte (256-bit) Profile Key.
// TODO(Diana): profile_key should be `&str`, but i'm unsure if I'm allowed to change the API.
#[allow(clippy::ptr_arg)]
pub fn get_unidentified_access_for_key(profile_key: &String) -> crate::Result<Vec<u8>> {
	let profile_key_bytes = base64::decode(profile_key)?;
	let profile_key = aes_gcm::Key::from_slice(profile_key_bytes.as_slice());
	let cipher = aes_gcm::Aes256Gcm::new(profile_key);
	//Libsignal-service-java enciphers 16 zeroes with a (re-used) nonce of 12 zeroes
	//to get this access key, unless I am horribly misreading it.
	let zeroes: [u8; 16] = [0; 16];
	let nonce: [u8; 12] = [0; 12];
	let nonce = Nonce::from_slice(&nonce);

	let payload = Payload {
		msg: &zeroes,
		aad: b"",
	};

	Ok(cipher.encrypt(nonce, payload)?)
}


#[derive(thiserror::Error, Debug)]
pub enum UnidentifiedAccessError {
	#[error("Cannot generate an unidentified access key for user {0:?}: We do not know their profile key! This would not matter for a user with UnidentifiedAccessMode::UNRESTRICTED.")]
	NoProfileKey(Uuid),
	#[error("Tried to generate an unidentified access key for peer {0:?}, but this user has disabled unidentified access!")]
	PeerDisallowsSealedSender(Uuid),
	#[error("Cannot generate an unidentified access key for address {0:?} as that is not a recognized peer.")]
	UnrecognizedUser(AuxinAddress),
	#[error("Attempted to generate an unidentified access key for peer {0:?}, but this user has no profile field whatsoever on record with this Auxin instance. We cannot retrieve their profile key.",)]
	NoProfile(Uuid),
}

impl AuxinContext {
	/// Generate an unidentified-access key for a user who accepts unrestricted unidentified access.
	fn get_unidentified_access_unrestricted(&mut self) -> crate::Result<Vec<u8>> {
		let bytes = [0u8; 16];

		Ok(Vec::from(bytes))
	}

	/// Generate an unidentified access key for a Signal peer, querying self.peer_cache to see what their unidentified access mode is.
	///
	/// # Arguments
	///
	/// * `peer_address` - The peer for whom to generate an unidentified access key.
	pub fn get_unidentified_access_for(
		&mut self,
		peer_address: &AuxinAddress,
	) -> crate::Result<Vec<u8>> {
		let peer = self.peer_cache.get(peer_address);
		if peer.is_none() {
			return Err(Box::new(UnidentifiedAccessError::UnrecognizedUser (
				peer_address.clone(),
			)));
		}
		let peer = peer.unwrap();

		let uuid = peer.uuid.unwrap();

		match &peer.profile {
			Some(p) => match p.unidentified_access_mode {
				UnidentifiedAccessMode::UNRESTRICTED => {
					debug!(
						"User {} has unrestricted unidentified access, generating random key.",
						uuid.to_string()
					);
					Ok(self.get_unidentified_access_unrestricted()?)
				}
				UnidentifiedAccessMode::ENABLED => {
					debug!("User {} accepts unidentified sender messages, generating an unidentified access key from their profile key.", uuid.to_string());
					match &peer.profile_key {
						Some(pk) => Ok(get_unidentified_access_for_key(pk)?),
						None => Err(Box::new(UnidentifiedAccessError::NoProfileKey(uuid))),
					}
				}
				UnidentifiedAccessMode::DISABLED => Err(Box::new(
					UnidentifiedAccessError::PeerDisallowsSealedSender(uuid),
				)),
			},
			None => Err(Box::new(UnidentifiedAccessError::NoProfile(uuid))),
		}
	}
	/// Retrieve the Signal Context - a C-style pointer to a placeholder data type.
	/// The signal context is wrapped this way so that the borrow checker doesn't complain about this non-Send datatype.
	pub fn get_signal_ctx(&self) -> &SignalCtx {
		&self.ctx
	}
}