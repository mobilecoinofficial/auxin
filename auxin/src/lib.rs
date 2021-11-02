#![feature(string_remove_matches)]
#![feature(associated_type_bounds)]
#![deny(bare_trait_objects)]

use address::{AddressError, AuxinAddress, AuxinDeviceAddress, E164};
use aes_gcm::{
	aead::{Aead, NewAead, Payload},
	Aes256Gcm, Nonce,
};
use attachment::{
	download::{self, AttachmentDownloadError},
	upload::{AttachmentUploadError, PreUploadToken, PreparedAttachment},
};
use auxin_protos::{AttachmentPointer, Envelope};
use custom_error::custom_error;

use futures::TryFutureExt;
use libsignal_protocol::{
	message_decrypt_prekey, process_prekey_bundle, IdentityKey, IdentityKeyPair, IdentityKeyStore,
	InMemIdentityKeyStore, InMemPreKeyStore, InMemSenderKeyStore, InMemSessionStore,
	InMemSignedPreKeyStore, PreKeySignalMessage, ProtocolAddress, PublicKey, SenderCertificate,
	SessionRecord, SessionStore, SignalProtocolError,
};
use log::{debug, error, info, warn};

use message::{MessageIn, MessageInError, MessageOut};
use net::{api_paths::SIGNAL_CDN, AuxinHttpsConnection, AuxinNetManager};
use protobuf::CodedInputStream;
use serde_json::json;
use std::{
	collections::{HashMap, HashSet},
	convert::TryFrom,
	error::Error,
	fmt::Debug,
	time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub mod address;
pub mod attachment;
pub mod discovery;
pub mod message;
pub mod net;
pub mod receiver;
pub mod state;

pub use message::Timestamp;

/// Self-signing root cert for TLS connections to Signal's web API..
pub const SIGNAL_TLS_CERT: &str = include_str!("../data/whisper.pem");
/// Trust anchor for IAS - required to validate certificate chains for remote SGX attestation.
pub const IAS_TRUST_ANCHOR: &[u8] = include_bytes!("../data/ias.der");

use rand::{CryptoRng, Rng, RngCore};
use state::{
	AuxinStateManager, PeerIdentity, PeerInfoReply, PeerRecord, PeerRecordStructure, PeerStore,
	UnidentifiedAccessMode,
};

use crate::{
	attachment::download::EncryptedAttachment,
	discovery::{
		AttestationResponseList, DirectoryAuthResponse, DiscoveryRequest, DiscoveryResponse,
		ENCLAVE_ID,
	},
	message::{
		address_from_envelope, fix_protobuf_buf, remove_message_padding, AuxinMessageList,
		MessageContent, MessageSendMode,
	},
	net::common_http_headers,
	state::{try_excavate_registration_id, ForeignPeerProfile, ProfileResponse},
};

pub const PROFILE_KEY_LEN: usize = 32;

pub type ProfileKey = [u8; PROFILE_KEY_LEN];

#[derive(Clone, Debug, Default)]
pub struct AuxinConfig {}

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Generate a 64-bit unsigned Timestamp - this is the number of miliseconds since the
/// Unix Epoch, which was January 1st, 1970 00:00:00 UTC.
pub fn generate_timestamp() -> u64 {
	let now = SystemTime::now();
	now.duration_since(UNIX_EPOCH)
		.expect("Time went backwards")
		.as_millis() as u64
}

/// Retrieves trust root for all "Sealed Sender" messages.
pub fn sealed_sender_trust_root() -> PublicKey {
	PublicKey::deserialize(
		base64::decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF")
			.unwrap()
			.as_slice(),
	)
	.unwrap()
}

pub const DEFAULT_DEVICE_ID: u32 = 1;

#[derive(Clone)]
/// Basic signal protocol information and key secrets for the local signal node.
/// This is not intended to be used to represent peers - instead, this is your user account,
/// the identity with which interacting with the SIgnal Protocol.
/// Primarily includes credentials and identifying information
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
	pub fn build_sendercert_request<Body: Default>(&self) -> Result<http::Request<Body>> {
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
	ctx: libsignal_protocol::Context,
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
/// This contains all of the keys and session state required to send and receive SIgnal messages.
#[allow(unused)] // TODO: Remove this after we can send/remove a message.
				 // This is the structure that an AuxinStateHandler builds and saves.
pub struct AuxinContext {
	/// The LocalIdentity holds this node's public and private key, its profile key, pwssword, and its UUID and phone number.
	pub identity: LocalIdentity,
	/// A certificate used to send sealded-sender / unidentified-sender messages.
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
	pub sender_key_store: InMemSenderKeyStore,

	/// Configuration for the Auxin library.
	pub config: AuxinConfig,
	/// Should we show up as "Online" to other Signal users?
	pub report_as_online: bool,

	/// Signal context - pointer to a C data type.
	/// It seems like this is future-proofing on Signal's behalf, because
	/// the Signal's library never uses theis datatype directly even though
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
pub fn get_unidentified_access_for_key(profile_key: &String) -> Result<Vec<u8>> {
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

custom_error! { pub UnidentifiedAccessError
	NoProfileKey{uuid: Uuid} = "Cannot generate an unidentified access key for user {uuid}: We do not know their profile key! This would not matter for a user with UnidentifiedAccessMode::UNRESTRICTED.",
	PeerDisallowsSealedSender{uuid: Uuid} = "Tried to generatet an unidentified access key for peer {uuid}, but this user has disabled unidentified access!",
	UnrecognizedUser{address: AuxinAddress} = "Cannot generate an unidentified access key for address {address} as that is not a recognized peer.",
	NoProfile{uuid: Uuid} = "Attempted to generate an unidenttified access key for peer {uuid}, but this user has no profile field whatsoever on record with this Auxin instance. We cannot retrieve their profile key.",
}

impl AuxinContext {
	/// Generate an unidentified-access key for a user who accepts unrestricted unidentified access.
	///
	/// # Arguments
	///
	/// * `rng` - Mutable reference to a random number generator, which must be cryptographically-strong (i.e. implements the CryptoRng interface).
	fn get_unidentified_access_unrestricted<R>(&mut self, rng: &mut R) -> Result<Vec<u8>>
	where
		R: RngCore + CryptoRng,
	{
		let bytes: [u8; 16] = rng.gen();

		Ok(Vec::from(bytes))
	}

	/// Generate an unidentified access key for a Signal peer, querying self.peer_cache to see what their unidentified access mode is.
	///
	/// # Arguments
	///
	/// * `peer_address` - The peer for whom to generate an unidentified access key.
	/// * `rng` - Mutable reference to a random number generator, which must be cryptographically-strong (i.e. implements the CryptoRng interface).
	pub fn get_unidentified_access_for<R>(
		&mut self,
		peer_address: &AuxinAddress,
		rng: &mut R,
	) -> Result<Vec<u8>>
	where
		R: RngCore + CryptoRng,
	{
		let peer = self.peer_cache.get(peer_address);
		if peer.is_none() {
			return Err(Box::new(UnidentifiedAccessError::UnrecognizedUser {
				address: peer_address.clone(),
			}));
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
					Ok(self.get_unidentified_access_unrestricted(rng)?)
				}
				UnidentifiedAccessMode::ENABLED => {
					debug!("User {} accepts unidentified sender messages, generating an unidentified access key from their profile key.", uuid.to_string());
					match &peer.profile_key {
						Some(pk) => Ok(get_unidentified_access_for_key(pk)?),
						None => Err(Box::new(UnidentifiedAccessError::NoProfileKey { uuid })),
					}
				}
				UnidentifiedAccessMode::DISABLED => Err(Box::new(
					UnidentifiedAccessError::PeerDisallowsSealedSender { uuid },
				)),
			},
			None => Err(Box::new(UnidentifiedAccessError::NoProfile { uuid })),
		}
	}
	/// Retrieve the Signal Context - a C-style pointer to a placeholder data type.
	/// The signal context is wrapped this way so that the borrow checker doesn't complain about this non-Send datatype.
	pub fn get_signal_ctx(&self) -> &SignalCtx {
		&self.ctx
	}
}

/// An Auxin application which can send and receive Signal messages and interact with the Signal protocol.
/// Requires a network manager and a state manager implementation - these are separated out from Auxin proper,
/// so that Auxin can be used on many different platforms and in many different environments.
///
/// TODO: Consider renaming this - auxin is a toolkit, not a framework, and does not need to own your event loop (and as such this isn't an "app").
pub struct AuxinApp<R, N, S>
where
	R: RngCore + CryptoRng,
	N: AuxinNetManager,
	S: AuxinStateManager,
{
	/// An AuxinNetManager, used to make HTTPS and Websocket connections to Signal's servers.
	pub net: N,
	/// An AuxinStateManager, a trait for structures which can hold and manage Signal protocol state.
	/// This could be a filesystem, call out to a database - so long as it can load and store state for the application.
	pub state_manager: S,
	/// The AuxinContext, holds sessions, public keys of other users, and our public and private key, among other things.
	/// This contains all of the keys and session state required to send and receive SIgnal messages.
	pub context: AuxinContext,
	/// A random number generator, which must be cryptographically-strong (i.e. implements the CryptoRng interface).
	pub rng: R,
	/// HTTP connection, cached since we can get away with instantiating it on program start and keep using it throughout.
	pub(crate) http_client: N::C,
}

// Any error encountered when trying to initialize an AuxinApp.
custom_error! { pub AuxinInitError
	CannotConnect{msg: String} = "Attempt to connect to Signal via HTTPS failed: {msg}.",
	CannotRequestSenderCert{msg: String} = "Unable to send a \"Sender Certificate\" request: {msg}.",
}

#[derive(Debug, Clone)]
// Errors received when attempting to send a Signal message to another user.
pub enum SendMessageError {
	CannotMakeMessageRequest(String),
	CannotSendAuthUpgrade(String),
	SenderCertRetrieval(String),
	CannotSendAttestReq(String),
	CannotSendDiscoveryReq(String),
	PeerStoreIssue(String),
	PeerSaveIssue(String),
	MessageBuildErr(String),
	EndSessionErr(String),
}

impl std::fmt::Display for SendMessageError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			SendMessageError::CannotMakeMessageRequest(e) => write!(f, "Unable to send a message-send request: {}.", e),
			SendMessageError::CannotSendAuthUpgrade(e)  => write!(f, "Unable request auth upgrade: {}.", e),
			SendMessageError::SenderCertRetrieval(e) => write!(f, "Failed to retrieve a sencer certificate: {}.", e),
			SendMessageError::CannotSendAttestReq(e) => write!(f, "Unable to request attestations: {}.", e),
			SendMessageError::CannotSendDiscoveryReq(e) => write!(f, "Unable to send discovery request to remote secure enclave: {}.", e),
			SendMessageError::PeerStoreIssue(e) => write!(f, "An error was encountered while trying to make sure information for a peer is present, for the purposes of sending a message: {}.", e),
			SendMessageError::MessageBuildErr(e) => write!(f, "Could not build or encrypt Signal message content for send_message(): {}.", e),
			SendMessageError::PeerSaveIssue(e) => write!(f, "Couldn't save files for a peer's sessions and profile, as part of sending a message: {}.", e),
			SendMessageError::EndSessionErr(e) => write!(f, "Encountered an error while attempting to close out a session after sending an END_SESSION message: {}.", e),
		}
	}
}
impl std::error::Error for SendMessageError {}

// An error encountered while trying to retrieve another Signal user's payment address (MobileCoin public address)
custom_error! { pub PaymentAddressRetrievalError
	NoProfileKey{peer: AuxinAddress} = "Couldn't retrieve payment address for peer {peer} because we do not have a profile key on file for this user.",
	NoPeer{peer: AuxinAddress} = "Cannot retrieve payment address for peer {peer} because we have no record on this user!",
	NoPaymentAddressForUser{peer: AuxinAddress} = "Got profile information for {peer}, but no payment address was included.",
	EncodingError{peer: AuxinAddress, msg: String} = "Error encoding profile/payment-address request for {peer}: {msg}",
	DecodingError{peer: AuxinAddress, msg: String} = "Error decoding profile/payment-address response for {peer}: {msg}",
	DecryptingError{peer: AuxinAddress, msg: String} = "Error decrypting profile/payment-address response for {peer}: {msg}",
	UnidentifiedAccess{peer: AuxinAddress, msg: String} = "Error getting unidentified access for {peer}: {msg}",
	NoUuid{peer: AuxinAddress, err: AddressError} = "No Uuid for {peer}: {err}",
	ErrPeer{peer: AuxinAddress, err: String} = "Error loading peer {peer}: {err}",
}

/// An error encountered when an AuxinApp is attemping to handle an incoming envelope.
#[derive(Debug)]
pub enum HandleEnvelopeError {
	MessageDecodingErr(MessageInError),
	ProtocolErr(SignalProtocolError),
	PreKeyBundleErr(String),
	PreKeyNoAddress,
	UnknownEnvelopeType(Envelope),
	ProfileError(String),
}
impl std::fmt::Display for HandleEnvelopeError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			HandleEnvelopeError::MessageDecodingErr(e) => write!(f, "Hit a message-decoding error while attempting to handle an envelope: {:?}", e),
			HandleEnvelopeError::ProtocolErr(e) => write!(f, "Encountered a protocol error while attempting to decode an envelope: {:?}", e),
			HandleEnvelopeError::PreKeyBundleErr(e) => write!(f, "Error occurred while handling a pre-key bundle: {}", e),
			HandleEnvelopeError::PreKeyNoAddress => write!(f, "No peer / foreign address on a pre-key bundle message!"),
			HandleEnvelopeError::UnknownEnvelopeType(e) => write!(f, "Received an \"Unknown\" message type from Websocket! Envelope is: {:?}",e),
			HandleEnvelopeError::ProfileError(e) => write!(f, "Attempted to retrieve profile information in the process of handling an envelope, but a problem was encountered: {:?}",e)
		}
	}
}

impl std::error::Error for HandleEnvelopeError {}

impl From<SignalProtocolError> for HandleEnvelopeError {
	fn from(val: SignalProtocolError) -> Self {
		HandleEnvelopeError::ProtocolErr(val)
	}
}
impl From<MessageInError> for HandleEnvelopeError {
	fn from(val: MessageInError) -> Self {
		HandleEnvelopeError::MessageDecodingErr(val)
	}
}

impl<R, N, S> AuxinApp<R, N, S>
where
	R: RngCore + CryptoRng,
	N: AuxinNetManager,
	S: AuxinStateManager,
{
	/// Construct an AuxinApp
	///
	/// # Arguments
	///
	/// * `local_phone_number` - This node's Signal user acocunt's phone number. TODO: Refactor this to allow accounts with no phone numbers when Signal fully implements usernames.
	/// * `config` - Configuation for various properties of this Signal app.
	/// * `net` - An AuxinNetManager, used to make HTTPS and Websocket connections to Signal's servers.
	/// * `state_manager` - An AuxinStateManager, a trait for structures which can hold and manage Signal protocol state. This could be a filesystem, call out to a database - so long as it can load and store state for the application.
	/// * `rng` - Mutable reference to a random number generator, which must be cryptographically-strong (i.e. implements the CryptoRng interface).
	pub async fn new(
		local_phone_number: E164,
		config: AuxinConfig,
		mut net: N,
		mut state_manager: S,
		rng: R,
	) -> Result<Self> {
		let local_identity = state_manager.load_local_identity(&local_phone_number)?;
		//TODO: Better error handling here.
		let http_client = net
			.connect_to_signal_https()
			.map_err(|e| {
				Box::new(AuxinInitError::CannotConnect {
					msg: format!("{:?}", e),
				})
			})
			.await?;

		let context = state_manager.load_context(&local_identity, config)?;

		Ok(Self {
			net,
			state_manager,
			context,
			rng,
			http_client,
		})
	}

	/// Checks to see if a recipient's information is loaded and takes all actions necessary to fill out a PeerRecord if not.
	///
	/// # Arguments
	///
	/// * `recipient_addr` - The address of the peer whose contact information we are checking (and retrieving if it's missing).
	pub async fn ensure_peer_loaded(&mut self, recipient_addr: &AuxinAddress) -> Result<()> {
		debug!(
			"Attempting to ensure all necessary information is present for peer {}",
			recipient_addr
		);

		let recipient_addr = self
			.context
			.peer_cache
			.complete_address(recipient_addr)
			.or(Some(recipient_addr.clone()))
			.unwrap();

		debug!("Completed address to: {}", recipient_addr);

		let recipient = self.context.peer_cache.get(&recipient_addr);

		//If we have their UUID and no peer entry, just write a new entry.
		if recipient.is_none() && recipient_addr.has_uuid() {
			let new_id = self.context.peer_cache.last_id + 1;
			self.context.peer_cache.last_id = new_id;

			let peer_record = PeerRecord {
				id: new_id,
				number: None,
				uuid: Some(*recipient_addr.get_uuid().unwrap()),
				profile_key: None,
				profile_key_credential: None,
				contact: None,
				profile: None,
				device_ids_used: HashSet::default(),
				registration_ids: HashMap::default(),
				identity: None,
			};
			self.context.peer_cache.push(peer_record);
		}
		//If we have no peer entry we have their phone number but not their UUID, or we have a peer entry with no UUID,
		//retrieve their UUID and store an entry.
		else if recipient.is_none() || recipient.unwrap().uuid.is_none() {
			self.retrieve_and_store_peer(recipient_addr.get_phone_number().unwrap())
				.await?;
		}

		let recipient_addr = self
			.context
			.peer_cache
			.complete_address(&recipient_addr)
			.unwrap();
		let recipient = self.context.peer_cache.get_mut(&recipient_addr).unwrap();

		// Was there a session which hadn't started?
		let mut missing_session = false;

		// Ensure our cache is consistent.
		// We should ABSOLUTELY have a UUID by now if this hasn't errored out.
		for device_id in recipient.device_ids_used.iter() {
			let device_addr = AuxinDeviceAddress {
				address: recipient_addr.clone(),
				device_id: *device_id,
			};
			let ctx = self.context.ctx.get();
			let protocol_addr = device_addr.uuid_protocol_address().unwrap();
			if let Ok(Some(session)) = self
				.context
				.session_store
				.load_session(&protocol_addr, ctx)
				.await
			{
				if !session.has_current_session_state() {
					// We do not have a current session state, go re-grab pre-keys.
					missing_session = true;
				}
				//Store the registration ID if we've got it.
				else if let Ok(reg_id) = session.remote_registration_id() {
					debug!(
						"Using registration ID {} for peer {} 's device #{}",
						reg_id, &recipient_addr, device_id
					);
					recipient.registration_ids.insert(*device_id, reg_id);
				} else {
					// See if we have a registration ID on file in an archived record.
					let old_id_maybe = try_excavate_registration_id(&session);
					match old_id_maybe {
						Ok(Some(old_id)) => {
							debug!("Found registration ID {} for peer {} 's device #{} in an old session. Using that.", old_id, &recipient_addr, device_id);
							recipient.registration_ids.insert(*device_id, old_id);
						}
						Err(e) => {
							// Digging around in old sessions was a "We are less likely to get ratelimited"
							// move anyway, so it is not critical that it succeeds.
							warn!("Encountered an error while digging for an old registration ID in a session for {} \
								   - silencing this error and assuming we don't have one (most likely we will need \
									to retrieve a registration ID from Signal's web API). Error was: {:?}", &recipient_addr, e);
						}
						Ok(None) => {} //Nothing found, no error, no action taken.
					}
				}
			}
		}

		debug!("Peer has device IDs {:?}", &recipient.device_ids_used);
		// Corrupt data / missing device list!
		if recipient.device_ids_used.is_empty()
			|| recipient.profile.is_none()
			|| (recipient.registration_ids.len() < recipient.device_ids_used.len())
		{
			debug!("Calling fill_peer_info() at the bottom of ensure_peer_loaded() because of missing device / registration ID.");
			self.fill_peer_info(&recipient_addr).await?;
		}
		//Session was recently cleared / no session?
		else if missing_session {
			debug!("Calling fill_peer_info() at the bottom of ensure_peer_loaded() because of missing session.");
			self.fill_peer_info(&recipient_addr).await?;
		}
		self.state_manager
			.save_peer_record(&recipient_addr, &self.context)?;
		self.state_manager
			.save_peer_sessions(&recipient_addr, &self.context)?;
		Ok(())
	}

	/// Send a message (any type of message) to a fellow Signal user. Returns the timestamp at which thsi message was generated.
	///
	/// # Arguments
	///
	/// * `recipient_addr` - The address of the peer to whom we're sending this message.
	/// * `message` - The message we are sending.
	pub async fn send_message(
		&mut self,
		recipient_addr: &AuxinAddress,
		message: MessageOut,
	) -> std::result::Result<Timestamp, SendMessageError> {
		info!("Start of send_message() at {}", generate_timestamp());

		let recipient_addr = self
			.context
			.peer_cache
			.complete_address(recipient_addr)
			.or(Some(recipient_addr.clone()))
			.unwrap();

		// Will this be the last mssage in a session that we send?
		let end_session = message.content.end_session;

		//Make sure we know everything about this user that we need to.
		self.ensure_peer_loaded(&recipient_addr)
			.await
			.map_err(|e| SendMessageError::PeerStoreIssue(format!("{:?}", e)))?;

		let recipient_addr = self
			.context
			.peer_cache
			.complete_address(&recipient_addr)
			.or(Some(recipient_addr.clone()))
			.unwrap();

		let message_list = AuxinMessageList {
			messages: vec![message],
			remote_address: recipient_addr.clone(),
		};

		// Can we do sealed sender messages here?
		let sealed_sender: bool = self
			.context
			.peer_cache
			.get(&recipient_addr)
			.unwrap()
			.supports_sealed_sender();

		let mode = match sealed_sender {
			true => {
				// Make sure we have a sender certificate to do this stuff with.
				self.retrieve_sender_cert()
					.await
					.map_err(|e| SendMessageError::SenderCertRetrieval(format!("{:?}", e)))?;
				MessageSendMode::SealedSender
			}
			false => MessageSendMode::Standard,
		};

		let timestamp = generate_timestamp();
		debug!("Building an outgoing message list with timestamp {}, which will be used as the message ID.", timestamp);
		let outgoing_push_list = message_list
			.generate_messages_to_all_devices(&mut self.context, mode, &mut self.rng, timestamp)
			.await
			.map_err(|e| SendMessageError::MessageBuildErr(format!("{:?}", e)))?;

		let request: http::Request<Vec<u8>> = outgoing_push_list
			.build_http_request(&recipient_addr, mode, &mut self.context, &mut self.rng)
			.map_err(|e| SendMessageError::CannotMakeMessageRequest(format!("{:?}", e)))?;
		let message_response = self
			.http_client
			.request(request)
			.map_err(|e| SendMessageError::CannotMakeMessageRequest(format!("{:?}", e)))
			.await?;

		let message_response_str = String::from_utf8(message_response.body().to_vec()).unwrap();
		debug!(
			"Got response to attempt to send message: {:?} {}",
			message_response, message_response_str
		);
		if !message_response.status().is_success() {
			return Err(SendMessageError::CannotMakeMessageRequest(format!(
				"Response to send message: {:?} {}",
				message_response, message_response_str
			)));
		}
		//Only necessary if fill_peer_info is called, and we do it in there.
		self.state_manager
			.save_peer_sessions(&recipient_addr, &self.context)
			.map_err(|e| SendMessageError::PeerSaveIssue(format!("{:?}", e)))?;

		// If this was intended as a session termination message, clear out session state.
		if end_session {
			self.clear_session(&recipient_addr)
				.await
				.map_err(|e| SendMessageError::EndSessionErr(format!("{:?}", e)))?;
		}

		info!("End of send_message() at {}", generate_timestamp());
		Ok(timestamp)
	}

	/// Get a sender certificate for ourselves from Signal's web API, so that we can send sealed_sender messages properly.
	/// Retrieved through a request to https://textsecure-service.whispersystems.org/v1/certificate/delivery
	pub async fn retrieve_sender_cert(&mut self) -> Result<()> {
		let trust_root = sealed_sender_trust_root();

		let sender_cert_request: http::Request<Vec<u8>> =
			self.context.identity.build_sendercert_request()?;
		let req_str: String = format!("{:?}", &sender_cert_request);
		//TODO: Better error handling here.
		let sender_cert_response = self
			.http_client
			.request(sender_cert_request)
			.map_err(|e| {
				Box::new(AuxinInitError::CannotRequestSenderCert {
					msg: format!("{:?}", e),
				})
			})
			.await?;
		if !sender_cert_response.status().is_success() {
			error!(
				"Response to sender certificate request was: {:?}",
				sender_cert_response
			);
			error!("Our request was: {}", req_str);
		}
		assert!(sender_cert_response.status().is_success());

		let sender_cert_response_str = String::from_utf8(sender_cert_response.body().to_vec())?;

		let cert_structure: serde_json::Value = serde_json::from_str(&sender_cert_response_str)?;
		let encoded_cert_str = cert_structure.get("certificate").unwrap();
		let temp_vec = base64::decode(encoded_cert_str.as_str().unwrap())?;
		let sender_cert = libsignal_protocol::SenderCertificate::deserialize(temp_vec.as_slice())?;

		if sender_cert.validate(&trust_root, generate_timestamp() as u64)? {
			debug!("Confirmed our sender certificate is valid!");
		} else {
			panic!("Invalid sender certificate!");
		}
		self.context.sender_certificate = Some(sender_cert);

		Ok(())
	}

	/// Retrieves and fills in core information about a peer that is necessary to send a mmessage to them.
	///
	/// # Arguments
	///
	/// * `recipient_addr` - The address of the peer whose information we are retrieving.
	pub async fn fill_peer_info(&mut self, recipient_addr: &AuxinAddress) -> Result<()> {
		let signal_ctx = self.context.get_signal_ctx().get();

		// Once you get here, retrieve_and_store_peer() shuld have already been called, so we should definitely have a UUID.
		let uuid = self
			.context
			.peer_cache
			.get(recipient_addr)
			.unwrap()
			.uuid
			.unwrap();

		{
			let mut profile_path: String =
				"https://textsecure-service.whispersystems.org/v1/profile/".to_string();
			profile_path.push_str(uuid.to_string().as_str());
			profile_path.push('/');

			let auth = self.context.identity.make_auth_header();

			let req = common_http_headers(http::Method::GET, profile_path.as_str(), auth.as_str())?;
			let req = req.body(Vec::default())?;

			let res = self.http_client.request(req).await?;

			let res_str = String::from_utf8(res.body().to_vec())?;
			debug!("Profile response: {:?}", res_str);
			let recipient = self.context.peer_cache.get_mut(&recipient_addr).unwrap();

			let prof: ForeignPeerProfile = serde_json::from_str(&res_str)?;

			recipient.profile = Some(prof.to_local());
		}

		let peer_info = self.request_peer_info(&uuid).await?;
		let decoded_key = base64::decode(&peer_info.identity_key)?;
		let identity_key = IdentityKey::decode(decoded_key.as_slice())?;

		for device in peer_info.devices.iter() {
			let recipient = self.context.peer_cache.get_mut(recipient_addr).unwrap();
			//Track device IDs used.
			recipient.device_ids_used.insert(device.device_id);
			//Track registration IDs.
			recipient
				.registration_ids
				.insert(device.device_id, device.registration_id);
			//Note that we are aware of this peer.
			let addr = ProtocolAddress::new(uuid.to_string(), device.device_id);
			//Save this peer's public key.
			self.context
				.identity_store
				.save_identity(&addr, &identity_key, signal_ctx)
				.await?;
		}

		{
			//And now for our own, signal-cli-compatible "Identity Store"
			let recipient = self.context.peer_cache.get_mut(recipient_addr).unwrap();
			if recipient.identity.is_none() {
				recipient.identity = Some(PeerIdentity {
					identity_key: peer_info.identity_key.clone(),
					trust_level: Some(1),
					added_timestamp: Some(generate_timestamp()),
				});
			}
		}

		let pre_key_bundles = peer_info.convert_to_pre_key_bundles()?;

		for (device_id, keys) in pre_key_bundles {
			let peer_address = ProtocolAddress::new(uuid.to_string(), device_id);
			// Initiate a session using foreign PreKey.
			process_prekey_bundle(
				&peer_address,
				&mut self.context.session_store,
				&mut self.context.identity_store,
				&keys,
				&mut self.rng,
				signal_ctx,
			)
			.await?;
		}

		self.state_manager
			.save_peer_record(recipient_addr, &self.context)?;
		self.state_manager
			.save_peer_sessions(recipient_addr, &self.context)?;
		Ok(())
	}

	/// Retrieve information for a peer for whom we have a phone number, but no UUID.
	///
	/// # Arguments
	///
	/// * `recipient_addr` - The address of the peer whose contact information we are retrieving.
	pub async fn retrieve_and_store_peer(&mut self, recipient_phone: &E164) -> Result<()> {
		let uuid = self.make_discovery_request(recipient_phone).await?;

		let new_id = self.context.peer_cache.last_id + 1;
		self.context.peer_cache.last_id = new_id;
		// TODO: Retrieve device IDs and such.
		let peer_record = PeerRecord {
			id: new_id,
			number: Some(recipient_phone.clone()),
			uuid: Some(uuid),
			profile_key: None,
			profile_key_credential: None,
			contact: None,
			profile: None,
			device_ids_used: HashSet::default(),
			registration_ids: HashMap::default(),
			identity: None,
		};

		self.context.peer_cache.push(peer_record);

		let address = AuxinAddress::Uuid(uuid);

		debug!("Calling fill_peer_info() from inside retrieve_and_store_peer() for uuid {} retrieved for phone number {}", &address, &recipient_phone);
		self.fill_peer_info(&address).await?;

		Ok(())
	}

	/// Retrieve public keys and device IDs of a peer.
	/// NOTE: You can get rate-limited on this method VERY easily. Try not to invoke it too often.
	///
	/// # Arguments
	///
	/// * `uuid` - The address of the peer whose information we are retrieving. A UUID is required for this.
	pub async fn request_peer_info(&self, uuid: &Uuid) -> Result<PeerInfoReply> {
		let uuid_str = uuid.to_string();
		let path: String = format!(
			"https://textsecure-service.whispersystems.org/v2/keys/{}/*",
			&uuid_str
		);

		let auth = self.context.identity.make_auth_header();

		let req = common_http_headers(http::Method::GET, path.as_str(), auth.as_str())?;
		let req = req.body(Vec::default())?;

		debug!("Making a request to {}, with structure: {:?}", &path, req);

		let res = self.http_client.request(req).await?;

		let res_str = String::from_utf8(res.body().to_vec())?;
		debug!("Peer keys response: {:?}", res_str);

		let info: PeerInfoReply = serde_json::from_str(&res_str)?;
		Ok(info)
	}

	/// Used to retrieve the UUID for a peer when we have their phone number and not their UUID.
	/// This gets an attestation and uses that to make a request to Signal's discovery service,
	/// which uses Intel SGX to ensure privacy for your contact list.
	///
	/// # Arguments
	///
	/// * `recipient_phone` - The phone number we are attempting to retrieve a corresponding UUID for.
	pub async fn make_discovery_request(&mut self, recipient_phone: &E164) -> Result<Uuid> {
		//Get upgraded auth for discovery / directory.
		let auth = self.context.identity.make_auth_header();
		let req = common_http_headers(
			http::Method::GET,
			"https://textsecure-service.whispersystems.org/v1/directory/auth",
			auth.as_str(),
		)?;
		let req = req.body(Vec::default())?;

		let auth_upgrade_response =
			self.http_client.request(req).await.map_err(|e| {
				Box::new(SendMessageError::CannotSendAuthUpgrade(format!("{:?}", e)))
			})?;
		assert!(auth_upgrade_response.status().is_success());

		let auth_upgrade_response_str = String::from_utf8(auth_upgrade_response.body().to_vec())?;

		let upgraded_auth: DirectoryAuthResponse =
			serde_json::from_str(&auth_upgrade_response_str)?;
		let mut upgraded_auth_token = upgraded_auth.username.clone();
		upgraded_auth_token.push(':');
		upgraded_auth_token.push_str(&upgraded_auth.password);
		upgraded_auth_token = base64::encode(upgraded_auth_token);
		debug!("Upgraded authorization token: {}", upgraded_auth_token);
		let mut upgraded_auth_header = String::from("Basic ");
		upgraded_auth_header.push_str(&upgraded_auth_token);
		debug!("Upgraded authorization header: {}", upgraded_auth_header);

		//Temporary Keypair for discovery
		let attestation_keys = libsignal_protocol::KeyPair::generate(&mut self.rng);
		let attestation_path = format!(
			"https://api.directory.signal.org/v1/attestation/{}",
			ENCLAVE_ID
		);
		let attestation_request = json!({
			"clientPublic": base64::encode(attestation_keys.public_key.public_key_bytes()?),
		});
		let mut req = common_http_headers(
			http::Method::PUT,
			&attestation_path,
			upgraded_auth_header.as_str(),
		)?;
		let attestation_request = attestation_request.to_string();
		req = req.header("Content-Type", "application/json; charset=utf-8");
		req = req.header("Content-Length", attestation_request.len());
		let req = req.body(attestation_request.into_bytes())?;

		debug!("Sending attestation request: {:?}", req);

		let attestation_response = self
			.http_client
			.request(req)
			.await
			.map_err(|e| Box::new(SendMessageError::CannotSendAttestReq(format!("{:?}", e))))?;

		let attestation_response_str = String::from_utf8(attestation_response.body().to_vec())?;
		let attestation_response_body: AttestationResponseList =
			serde_json::from_str(&attestation_response_str)?;

		attestation_response_body.verify_attestations()?;
		let att_list = attestation_response_body.decode_attestations(&attestation_keys)?;

		let receiver_vec = vec![recipient_phone.clone()];
		let query = DiscoveryRequest::new(&receiver_vec, &att_list, &mut self.rng)?;
		let query_str = serde_json::to_string_pretty(&query)?;
		debug!("Built discovery request {}", query_str);

		//we will need these cookies
		let cookies: Vec<&str> = attestation_response
			.headers()
			.iter()
			.filter_map(|(name, value)| {
				if name.as_str().eq_ignore_ascii_case("Set-Cookie") {
					value.to_str().ok()
				} else {
					None
				}
			})
			.collect();
		println!("{:?}", cookies);

		let mut filtered_cookies: Vec<String> = Vec::default();
		for cookie in cookies {
			let spl = cookie.split(';');
			for elem in spl {
				if elem.contains("ApplicationGatewayAffinityCORS")
					|| elem.contains("ApplicationGatewayAffinity")
				{
					filtered_cookies.push(elem.to_string());
				}
			}
		}

		let mut resulting_cookie_string = String::default();
		if !filtered_cookies.is_empty() {
			for elem in filtered_cookies.iter() {
				resulting_cookie_string.push_str(elem.as_str());
				if elem != filtered_cookies.last().unwrap() {
					resulting_cookie_string.push_str("; ");
				}
			}
		}
		println!("{:?}", resulting_cookie_string);

		let discovery_path = format!(
			"https://api.directory.signal.org/v1/discovery/{}",
			ENCLAVE_ID
		);

		let mut req = common_http_headers(
			http::Method::PUT,
			&discovery_path,
			upgraded_auth_header.as_str(),
		)?;

		req = req.header("Content-Type", "application/json; charset=utf-8");
		req = req.header("Content-Length", query_str.len());
		req = req.header("Cookie", resulting_cookie_string);
		let req = req.body(query_str.into_bytes())?;

		let response =
			self.http_client.request(req).await.map_err(|e| {
				Box::new(SendMessageError::CannotSendDiscoveryReq(format!("{:?}", e)))
			})?;
		debug!("{:?}", response);

		let response_str = String::from_utf8(response.body().to_vec())?;
		let discovery_response: DiscoveryResponse = serde_json::from_str(&response_str)?;
		let decrypted = discovery_response.decrypt(&att_list)?;
		let uuid = Uuid::from_slice(decrypted.as_slice())?;
		debug!(
			"Successfully decoded discovery response! The recipient's UUID is: {:?}",
			uuid
		);
		Ok(uuid)
	}

	/// Attempts to get a SignalPay aaddres / MobileCoin public address.
	///
	/// # Arguments
	///
	/// * `recipient` - The address of the peer we're attempting to get a payment address for.
	pub async fn retrieve_payment_address(
		&mut self,
		recipient_addr: &AuxinAddress,
	) -> std::result::Result<auxin_protos::PaymentAddress, PaymentAddressRetrievalError> {
		self.ensure_peer_loaded(recipient_addr).await.map_err(|e| {
			PaymentAddressRetrievalError::ErrPeer {
				peer: recipient_addr.clone(),
				err: format!("{:?}", e),
			}
		})?;
		//We may have just grabbed the UUID in ensure_peer_loaded() above, make sure we have a usable address.
		let recipient = self
			.context
			.peer_cache
			.complete_address(recipient_addr)
			.unwrap_or(recipient_addr.clone());

		if let Some(peer) = self.context.peer_cache.get(&recipient) {
			if let Some(profile_key) = &peer.profile_key {
				let mut profile_key_bytes: [u8; PROFILE_KEY_LEN] = [0; PROFILE_KEY_LEN];
				let temp_bytes = base64::decode(profile_key).map_err(|e| {
					PaymentAddressRetrievalError::EncodingError {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					}
				})?;
				profile_key_bytes.copy_from_slice(&(temp_bytes)[0..PROFILE_KEY_LEN]);

				let uuid =
					recipient
						.get_uuid()
						.map_err(|e| PaymentAddressRetrievalError::NoUuid {
							peer: recipient.clone(),
							err: e,
						})?;

				let randomness: [u8; 32] = self.rng.gen();
				let server_secret_params = zkgroup::api::ServerSecretParams::generate(randomness);
				let server_public_params = server_secret_params.get_public_params();
				let randomness: [u8; 32] = self.rng.gen();
				let zk_profile_key = zkgroup::api::profiles::ProfileKey::create(profile_key_bytes);
				let version = zk_profile_key.get_profile_key_version(*uuid.as_bytes());
				let request_context = server_public_params
					.create_profile_key_credential_request_context(
						randomness,
						*uuid.as_bytes(),
						zk_profile_key,
					);
				let request = request_context.get_request();
				let encoded_request = hex::encode(&bincode::serialize(&request).unwrap());

				let version_bytes = bincode::serialize(&version).map_err(|e| {
					PaymentAddressRetrievalError::EncodingError {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					}
				})?;
				let version_string = String::from_utf8_lossy(&version_bytes);

				let get_path = format!(
					"https://textsecure-service.whispersystems.org/v1/profile/{}/{}/{}",
					uuid.to_string(),
					version_string,
					encoded_request
				);

				let unidentified_access = self
					.context
					.get_unidentified_access_for(&recipient, &mut self.rng)
					.map_err(|e| PaymentAddressRetrievalError::UnidentifiedAccess {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					})?;
				let unidentified_access = base64::encode(unidentified_access);
				let req = common_http_headers(
					http::Method::GET,
					&get_path,
					&self.context.identity.make_auth_header(),
				)
				.map_err(|e| PaymentAddressRetrievalError::EncodingError {
					peer: recipient.clone(),
					msg: format!("{:?}", e),
				})?
				.header("Unidentified-Access-Key", unidentified_access)
				.body(Vec::default())
				.map_err(|e| PaymentAddressRetrievalError::EncodingError {
					peer: recipient.clone(),
					msg: format!("{:?}", e),
				})?;
				debug!("Requesitng profile key credential with {:?}", req);
				let response = self.http_client.request(req).await.map_err(|e| {
					PaymentAddressRetrievalError::EncodingError {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					}
				})?;

				let response_str = String::from_utf8(response.body().to_vec()).map_err(|e| {
					PaymentAddressRetrievalError::DecodingError {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					}
				})?;

				let response_structure: ProfileResponse = serde_json::from_str(&response_str)
					.map_err(|e| PaymentAddressRetrievalError::DecodingError {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					})?;

				if let Some(address_b64) = &response_structure.payment_address {
					let key = aes_gcm::Key::from_slice(&profile_key_bytes);
					let cipher = Aes256Gcm::new(key);

					let payment_address_bytes = base64::decode(&address_b64).map_err(|e| {
						PaymentAddressRetrievalError::DecodingError {
							peer: recipient.clone(),
							msg: format!("{:?}", e),
						}
					})?;

					//                              Nonce + content + ????
					assert!(payment_address_bytes.len() > 12 + 16);

					let mut nonce_bytes: [u8; 12] = [0; 12];
					nonce_bytes.copy_from_slice(&payment_address_bytes[0..12]);

					let nonce = Nonce::from_slice(&nonce_bytes);

					let content_len = payment_address_bytes.len() - nonce_bytes.len();

					let mut content_bytes: Vec<u8> = vec![0; content_len];

					// Reminder that slicing [num..] in Rust gives you from index num to the end of the container.
					content_bytes.copy_from_slice(&payment_address_bytes[nonce_bytes.len()..]);
					let payload = Payload {
						msg: &content_bytes,
						aad: b"",
					};
					let decryption_result = cipher.decrypt(nonce, payload).map_err(|e| {
						PaymentAddressRetrievalError::DecryptingError {
							peer: recipient.clone(),
							msg: format!("{:?}", e),
						}
					})?;

					// 4 bits len - - 32 bit (signed?) integer describing buffer length.
					let max_length = (decryption_result.len() - 4) as i32;
					let mut tag_bytes: [u8; 4] = [0; 4];
					tag_bytes.copy_from_slice(&decryption_result[0..4]);
					let length = i32::from_le_bytes(tag_bytes);
					assert!(length < max_length);
					assert!(length > 0);

					let length = length as usize;
					let mut content_bytes: Vec<u8> = vec![0; length];

					// 4 bytes for length - offset by that. Get "length" bytes affter the length tag itself.
					// The rest is padding.
					content_bytes.copy_from_slice(&decryption_result[4..(length + 4)]);

					let fixed_buf = fix_protobuf_buf(&content_bytes).map_err(|e| {
						PaymentAddressRetrievalError::DecodingError {
							peer: recipient.clone(),
							msg: format!("{:?}", e),
						}
					})?;
					let mut reader = protobuf::CodedInputStream::from_bytes(&fixed_buf);
					let payment_address: auxin_protos::PaymentAddress = reader
						.read_message()
						.map_err(|e| PaymentAddressRetrievalError::DecodingError {
							peer: recipient.clone(),
							msg: format!("{:?}", e),
						})?;
					return Ok(payment_address);
				};
				Err(PaymentAddressRetrievalError::NoPaymentAddressForUser {
					peer: recipient.clone(),
				})
			} else {
				Err(PaymentAddressRetrievalError::NoProfileKey {
					peer: recipient.clone(),
				})
			}
		} else {
			Err(PaymentAddressRetrievalError::NoPeer {
				peer: recipient.clone(),
			})
		}
	}

	/// Download an attachment from Signal's CDN.
	///
	/// # Arguments
	///
	/// * `attachment` - A SignalService attachment pointer, containing all infromation required to retrieve and decrypt this attachment. .
	pub async fn retrieve_attachment(
		&self,
		attachment: &AttachmentPointer,
	) -> std::result::Result<EncryptedAttachment, AttachmentDownloadError> {
		//TODO: Test to see if there is any time when we need to use a different CDN address.
		download::retrieve_attachment(attachment.clone(), self.http_client.clone(), SIGNAL_CDN)
			.await
	}

	/// Retrieve a pre-upload token that you can use to upload an attachment to Signal's CDN.
	/// Note that no information about what we're going to upload is required - this just generates
	/// an ID that we can then turn around and use for an upload
	pub async fn request_upload_id(
		&self,
	) -> std::result::Result<PreUploadToken, AttachmentUploadError> {
		let auth = self.context.identity.make_auth_header();
		attachment::upload::request_attachment_token(
			("Authorization", auth.as_str()),
			self.http_client.clone(),
		)
		.await
	}

	/// Upload an attahcment to Signal's CDN.
	///
	/// # Arguments
	///
	/// * `upload_attributes` - The pre-upload token retrieved via request_upload_id().
	/// * `attachment` - An attachment which has been encrypted by auxin::attachment::upload::encrypt_attachment()
	pub async fn upload_attachment(
		&self,
		upload_attributes: &PreUploadToken,
		attachment: &PreparedAttachment,
	) -> std::result::Result<AttachmentPointer, AttachmentUploadError> {
		let auth = self.context.identity.make_auth_header();
		let result = attachment::upload::upload_attachment(
			upload_attributes,
			attachment,
			("Authorization", auth.as_str()),
			self.http_client.clone(),
			SIGNAL_CDN,
		)
		.await?;
		Ok(result)
	}

	/// Returns a reference to our cached HTTP client.
	pub fn get_http_client(&self) -> &N::C {
		&self.http_client
	}
	/// Returns a mutable reference to our cached HTTP client.
	pub fn get_http_client_mut(&mut self) -> &mut N::C {
		&mut self.http_client
	}

	async fn record_ids_from_message(&mut self, message: &MessageIn) -> Result<()> {
		let completed_addr = self
			.context
			.peer_cache
			.complete_address(&message.remote_address.address)
			.unwrap_or(message.remote_address.address.clone());
		// Make sure we know about their device ID.
		let peer_maybe = self
			.context
			.peer_cache
			.get_mut(&message.remote_address.address);
		if let Some(peer) = peer_maybe {
			peer.device_ids_used
				.insert(message.remote_address.device_id);
			// Did the session just get a registration ID?
			let ctx = self.context.ctx.get();
			let completed_device_addr = AuxinDeviceAddress {
				address: completed_addr,
				device_id: message.remote_address.device_id,
			};
			let protocol_addr = completed_device_addr.uuid_protocol_address().unwrap();
			if let Ok(Some(session)) = self
				.context
				.session_store
				.load_session(&protocol_addr, ctx)
				.await
			{
				//Store the registration ID if we've got it.
				if let Ok(reg_id) = session.remote_registration_id() {
					peer.registration_ids
						.insert(completed_device_addr.device_id, reg_id);
				}
			}
		}
		Ok(())
	}

	/// Handle a received envelope and decode it into a MessageIn if it represents data meant to be read by the end user.
	/// If it's a message internal to the protocol (i.e. it's a PreKey Bundle), it will return Ok(None).
	/// If it's something intended to be read by the end-user / externally to Signal, it returns a Some(MessageIn)
	///
	/// # Arguments
	///
	/// * `envelope` - The Signal Service envelope to process.
	pub async fn handle_inbound_envelope(
		&mut self,
		envelope: Envelope,
	) -> std::result::Result<Option<MessageIn>, HandleEnvelopeError> {
		match envelope.get_field_type() {
			auxin_protos::Envelope_Type::UNKNOWN => {
				Err(HandleEnvelopeError::UnknownEnvelopeType(envelope))
			}
			auxin_protos::Envelope_Type::CIPHERTEXT => Ok(Some({
				let result =
					MessageIn::from_ciphertext_message(envelope, &mut self.context, &mut self.rng)
						.await?;

				self.record_ids_from_message(&result).await.unwrap();

				if result.content.end_session {
					debug!("Got an END_SESSION flag from a peer, clearing out their session state. Message was: {:?}", result);
					self.clear_session(&result.remote_address.address)
						.await
						.unwrap(); // TODO: Proper error handling on clear_session();
				}

				//Return
				result
			})),
			auxin_protos::Envelope_Type::KEY_EXCHANGE => todo!(),
			auxin_protos::Envelope_Type::PREKEY_BUNDLE => {
				if !(envelope.has_sourceUuid() || envelope.has_sourceE164()) {
					return Err(HandleEnvelopeError::PreKeyNoAddress);
				}
				debug!(
					"Decoding PreKeyBundle envelope from source: (E164: {}, UUID: {})",
					envelope.get_sourceE164(),
					envelope.get_sourceUuid()
				);

				// Build our remote address if this is not a sealed sender message.
				let remote_address = address_from_envelope(&envelope);
				let remote_address = remote_address.map(|a| {
					let mut new_addr = a.clone();
					new_addr.address = self
						.context
						.peer_cache
						.complete_address(&a.address)
						.unwrap_or(a.address.clone());
					new_addr
				});

				if remote_address.is_none() {
					return Err(HandleEnvelopeError::PreKeyNoAddress);
				}
				let remote_address = remote_address.unwrap();

				let protocol_address = remote_address.uuid_protocol_address().unwrap();
				let pre_key_message = PreKeySignalMessage::try_from(envelope.get_content())?;

				let ctx = self.context.get_signal_ctx().ctx;

				// Update registration ID
				let reg_id = pre_key_message.registration_id();

				// Make sure we know about their device ID.
				let peer_maybe = self.context.peer_cache.get_mut(&remote_address.address);
				if let Some(peer) = peer_maybe {
					debug!("Updating existing peer with IDs from pre-key message.");
					peer.device_ids_used.insert(remote_address.device_id);
					//Record registration ID, which a prey key message will always have.
					peer.registration_ids
						.insert(remote_address.device_id, reg_id);
				}
				//If we have never encountered this peer before, go get information on them remotely.
				self.ensure_peer_loaded(&remote_address.address)
					.await
					.map_err(|e| HandleEnvelopeError::ProfileError(format!("{:?}", e)))?;

				let decrypted = message_decrypt_prekey(
					&pre_key_message,
					&protocol_address,
					&mut self.context.session_store,
					&mut self.context.identity_store,
					&mut self.context.pre_key_store,
					&mut self.context.signed_pre_key_store,
					&mut self.rng,
					ctx,
				)
				.await?;

				let unpadded_message = remove_message_padding(&decrypted)
					.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?;
				let fixed_buf = fix_protobuf_buf(&unpadded_message)
					.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?;

				let mut reader: CodedInputStream =
					CodedInputStream::from_bytes(fixed_buf.as_slice());

				let content: auxin_protos::Content = reader
					.read_message()
					.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?;

				debug!("Produced content from PreKeyBundle message: {:?}", &content);

				//If they're providing us with their profile key, store / update that information.
				MessageIn::update_profile_key_from(
					&content,
					&remote_address.address,
					&mut self.context,
				)?;

				if content.has_dataMessage() {
					let data_message = content.get_dataMessage();
					if data_message.has_flags() && data_message.has_profileKey() {
						// If this is a profile key distribution message and nothing else, return without trying to generate a MessageIn
						if data_message.get_flags() & 4 > 0 {
							return Ok(None);
						}

						// If this is an end session message, clear out the session for this peer.
						//if data_message.get_flags() & 1 > 0 {
						//	self.clear_session(&remote_address.address).await.unwrap(); //TODO: proper error hanndling here.
						//}
						//Prekey distribution messages should never be end-session.
					}
				}

				let result = MessageIn {
					content: MessageContent::try_from(content)?,
					remote_address,
					timestamp: envelope.get_timestamp(),
					timestamp_received: generate_timestamp(),
					server_guid: envelope.get_serverGuid().to_string(),
				};

				self.record_ids_from_message(&result).await.unwrap();

				if result.content.end_session {
					debug!("Got an END_SESSION flag from a peer as part of a PreKeyBundle message, clearing out their session state. Message was: {:?}", &result);
					self.clear_session(&result.remote_address.address)
						.await
						.unwrap(); // TODO: Proper error handling on clear_session();
				}

				Ok(Some(result))
			}
			auxin_protos::Envelope_Type::RECEIPT => Ok(Some({
				let result = MessageIn::from_receipt(envelope, &mut self.context).await?;

				//Receipts cannot be end-session messages.
				self.record_ids_from_message(&result).await.unwrap();

				result
			})),
			auxin_protos::Envelope_Type::UNIDENTIFIED_SENDER => Ok(Some({
				let result = MessageIn::from_sealed_sender(envelope, &mut self.context).await?;

				self.record_ids_from_message(&result).await.unwrap();

				if result.content.end_session {
					debug!("Got an END_SESSION flag from a peer, clearing out their session state. Message was: {:?}", &result);
					self.clear_session(&result.remote_address.address)
						.await
						.unwrap(); // TODO: Proper error handling on clear_session();
				}

				//Return
				result
			})),
			auxin_protos::Envelope_Type::PLAINTEXT_CONTENT => todo!(),
		}
	}

	/// Clear out all local session data with the specified peer.
	/// Note that this doesn't send a message with the END_SESSION flag set,
	/// it only gets rid of session data on our end.
	///
	/// To end a session, send a message with the end_session field set to true.
	///
	/// # Arguments
	///
	/// * `peer` - The Signal Service address to end our session with.
	pub async fn clear_session(&mut self, peer_addr: &AuxinAddress) -> Result<()> {
		self.state_manager.end_session(peer_addr, &self.context)?;

		// Pull up the relevant peer
		let peer_record = match self.context.peer_cache.get(&peer_addr) {
			Some(a) => a,
			// We do not need to delete what is not there.
			None => {
				return Ok(());
			}
		};

		// Archive or generate-fresh a new session store.
		for device_id in peer_record.device_ids_used.iter() {
			let device_addr = AuxinDeviceAddress {
				address: peer_addr.clone(),
				device_id: *device_id,
			};

			let protocol_addr = device_addr.uuid_protocol_address()?;

			let session = self
				.context
				.session_store
				.load_session(&protocol_addr, self.context.get_signal_ctx().get())
				.await;

			if let Ok(Some(mut s)) = session {
				s.archive_current_state()?;
				self.context
					.session_store
					.store_session(&protocol_addr, &s, self.context.get_signal_ctx().get())
					.await?;
			} else {
				let new_record = SessionRecord::new_fresh();
				self.context
					.session_store
					.store_session(
						&protocol_addr,
						&new_record,
						self.context.get_signal_ctx().get(),
					)
					.await?;
			}
		}

		self.state_manager
			.save_peer_sessions(&peer_addr, &self.context)?;

		Ok(())
	}
}

impl<R, N, S> Drop for AuxinApp<R, N, S>
where
	R: RngCore + CryptoRng,
	N: AuxinNetManager,
	S: AuxinStateManager,
{
	fn drop(&mut self) {
		// Make sure all data gets saved first.
		self.state_manager
			.save_entire_context(&self.context)
			.unwrap();
		self.state_manager.flush(&self.context).unwrap();
	}
}

pub use crate::receiver::{AuxinReceiver, ReceiveError};
