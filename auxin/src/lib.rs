// Copyright (c) 2021 MobileCoin Inc.
// Copyright (c) 2021 Emily Cultip

#![feature(string_remove_matches)]
#![feature(associated_type_bounds)]
#![feature(result_flattening)]
#![deny(bare_trait_objects)]

//! Developer (and bot) friendly wrapper around the Signal protocol.

use address::{AuxinAddress, AuxinDeviceAddress, E164};
use aes_gcm::{
	aead::{Aead, NewAead, Payload},
	Aes256Gcm, Nonce,
};
use attachment::{
	download::{self, AttachmentDownloadError},
	upload::{
		AttachmentEncryptError, AttachmentUploadError, AttachmentUploadToken, PreUploadToken,
		PreparedAttachment,
	},
};
use auxin_protos::{AttachmentPointer, Envelope};

use custom_error::custom_error;
use futures::TryFutureExt;
use groups::GroupApiError;
use libsignal_protocol::{
	message_decrypt_prekey, process_prekey_bundle, IdentityKey, IdentityKeyStore,
	PreKeySignalMessage, ProtocolAddress, PublicKey, SessionRecord, SessionStore,
	SignalProtocolError, SenderKeyDistributionMessage,
};
use log::{debug, error, info, trace, warn};

use message::{MessageIn, MessageInError, MessageOut};
use net::{
	api_paths::{SIGNAL_CDN, SIGNAL_CDN_2},
	AuxinHttpsConnection, AuxinNetManager,
};
use profile::ProfileConfig;
use protobuf::CodedInputStream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use zkgroup::groups::{GroupSecretParams, GroupMasterKey};
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
pub mod context;
pub mod discovery;
pub mod groups;
pub mod message;
pub mod net;
pub mod profile;
pub mod profile_cipher;
pub mod state;
pub mod utils;

pub use context::*;
pub use message::Timestamp;

/// Self-signing root cert for TLS connections to Signal's web API..
pub const SIGNAL_TLS_CERT: &str = include_str!("../data/whisper.pem");
/// Trust anchor for IAS - required to validate certificate chains for remote SGX attestation.
pub const IAS_TRUST_ANCHOR: &[u8] = include_bytes!("../data/ias.der");

use rand::{CryptoRng, Rng, RngCore};
use state::{AuxinStateManager, PeerIdentity, PeerInfoReply, PeerRecord, PeerStore};

use crate::{
	attachment::{download::EncryptedAttachment, upload::content_type_from_filename},
	discovery::{
		AttestationResponseList, DirectoryAuthResponse, DiscoveryRequest, DiscoveryResponse,
		ENCLAVE_ID,
	},
	message::{
		address_from_envelope, fix_protobuf_buf, remove_message_padding, AuxinMessageList,
		MessageContent, MessageSendMode,
	},
	net::common_http_headers,
	profile::{build_set_profile_request, ProfileResponse},
	profile_cipher::ProfileCipher,
	state::{
		try_excavate_registration_id, ForeignPeerProfile, PeerProfile, UnidentifiedAccessMode,
	}, groups::{sender_key::{SenderKeyName, process_sender_key}, InMemoryCredentialsCache, GroupsManager, get_server_public_params, get_group_members_without, GroupMemberInfo, GroupIdV2},
};

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Generate a 64-bit unsigned Timestamp - this is the number of milliseconds since the
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

/// (Try to) read a raw byte buffer as a Signal Envelope (defined by a protocol buffer).
pub fn read_envelope_from_bin(buf: &[u8]) -> crate::Result<auxin_protos::Envelope> {
	let new_buf = fix_protobuf_buf(&Vec::from(buf))?;
	let mut reader = protobuf::CodedInputStream::from_bytes(new_buf.as_slice());
	Ok(reader.read_message()?)
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
	/// This contains all of the keys and session state required to send and receive Signal messages.
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
/// Received with a 409 http response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MismatchedDevices {
	pub missing_devices: Vec<u32>,
	pub extra_devices: Vec<u32>,
}
/// Received with a 410 http response, most often in a group context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDevices {
	pub stale_devices: Vec<u32>,
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
	AttemptTwoFail(String),
}

impl std::fmt::Display for SendMessageError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			SendMessageError::CannotMakeMessageRequest(e) => write!(f, "Unable to send a message-send request: {}.", e),
			SendMessageError::CannotSendAuthUpgrade(e)  => write!(f, "Unable request auth upgrade: {}.", e),
			SendMessageError::SenderCertRetrieval(e) => write!(f, "Failed to retrieve a sender certificate: {}.", e),
			SendMessageError::CannotSendAttestReq(e) => write!(f, "Unable to request attestations: {}.", e),
			SendMessageError::CannotSendDiscoveryReq(e) => write!(f, "Unable to send discovery request to remote secure enclave: {}.", e),
			SendMessageError::PeerStoreIssue(e) => write!(f, "An error was encountered while trying to make sure information for a peer is present, for the purposes of sending a message: {}.", e),
			SendMessageError::MessageBuildErr(e) => write!(f, "Could not build or encrypt Signal message content for send_message(): {}.", e),
			SendMessageError::PeerSaveIssue(e) => write!(f, "Couldn't save files for a peer's sessions and profile, as part of sending a message: {}.", e),
			SendMessageError::EndSessionErr(e) => write!(f, "Encountered an error while attempting to close out a session after sending an END_SESSION message: {}.", e),
			SendMessageError::AttemptTwoFail(e) => write!(f, "Second attempt to send a message (after mismatched device list) failed: {}.", e),
		}
	}
}
impl std::error::Error for SendMessageError {}

// An error encountered while trying to retrieve another Signal user's payment address (MobileCoin public address)
#[derive(Debug, Clone)]
pub enum PaymentAddressRetrievalError {
	CouldntGetProfile(ProfileRetrievalError),
	NoPaymentAddressForUser(AuxinAddress),
	EncodingError(AuxinAddress, String),
	DecodingError(AuxinAddress, String),
	DecryptingError(AuxinAddress, String),
}

impl std::fmt::Display for PaymentAddressRetrievalError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			PaymentAddressRetrievalError::CouldntGetProfile(err) => write!(f, "Unable to retrieve a user profile for the purpose of getting a mobilecoin address: {:?}", err),
			PaymentAddressRetrievalError::NoPaymentAddressForUser(peer) => write!(f, "Attempted to get a payment address for user {:?}, but this user has not set a payment address.", peer),
			PaymentAddressRetrievalError::EncodingError(peer, msg) => write!(f, "Error encoding profile request for {:?}: {}", peer, msg),
			PaymentAddressRetrievalError::DecodingError(peer, msg) => write!(f, "Error decoding profile response for {:?}: {}", peer, msg),
			PaymentAddressRetrievalError::DecryptingError(peer, msg) => write!(f, "Error decrypting profile response for {:?}: {}", peer, msg),
		}
	}
}
impl std::error::Error for PaymentAddressRetrievalError {}

#[derive(Debug, Clone)]
pub enum ProfileRetrievalError {
	NoProfileKey(AuxinAddress),
	NoPeer(AuxinAddress),
	EncodingError(AuxinAddress, String),
	DecodingError(AuxinAddress, String),
	DecryptingError(AuxinAddress, String),
	UnidentifiedAccess(AuxinAddress, String),
	NoUuid(AuxinAddress, String),
	ErrPeer(AuxinAddress, String),
}

impl std::fmt::Display for ProfileRetrievalError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			ProfileRetrievalError::NoProfileKey(peer) => write!(f, "Couldn't retrieve payment address for peer {:?} because we do not have a profile key on file for this user.", peer),
			ProfileRetrievalError::NoPeer(peer) => write!(f, "Cannot retrieve payment address for peer {:?} because we have no record on this user!", peer),
			ProfileRetrievalError::EncodingError(peer, msg) => write!(f, "Error encoding profile request for {:?}: {}", peer, msg),
			ProfileRetrievalError::DecodingError(peer, msg) => write!(f, "Error decoding profile response for {:?}: {}", peer, msg),
			ProfileRetrievalError::DecryptingError(peer, msg) => write!(f, "Error decrypting profile response for {:?}: {}", peer, msg),
			ProfileRetrievalError::UnidentifiedAccess(peer, msg) => write!(f, "Error getting unidentified access for {:?}: {}", peer, msg),
			ProfileRetrievalError::NoUuid(peer, err) => write!(f, "No Uuid for {:?}: {}", peer, err),
			ProfileRetrievalError::ErrPeer(peer, err) => write!(f, "Error loading peer {:?}: {}", peer, err),
		}
	}
}
impl std::error::Error for ProfileRetrievalError {}

impl From<ProfileRetrievalError> for PaymentAddressRetrievalError {
	fn from(val: ProfileRetrievalError) -> Self {
		PaymentAddressRetrievalError::CouldntGetProfile(val)
	}
}

/// An error encountered when an AuxinApp is attempting to send or receive group messages.
#[derive(Debug)]
pub enum GroupsError {
	FillPeerInfoError(String),
	InvalidMasterKeyLength(usize),
	ApiError(GroupApiError),
}

impl std::fmt::Display for GroupsError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			GroupsError::FillPeerInfoError(e) => write!(f, "There were unknown users in the group. While trying to retrieve device Ids for them, an error was encountered: {:?}", e),
			GroupsError::InvalidMasterKeyLength(size) => write!(f, "Invalid Master Key length on a Groups data message. The size was {} bytes and a Master Key is expected to be 32 bytes long.", size),
			GroupsError::ApiError(e) => write!(f, "Groups API error: {:?}.", e),
		}
	}
}
impl std::error::Error for GroupsError {}
impl From<GroupApiError> for GroupsError {
	fn from(val: GroupApiError) -> Self {
		GroupsError::ApiError(val)
	}
}

/// An error encountered when an AuxinApp is attempting to handle an incoming envelope.
#[derive(Debug)]
pub enum HandleEnvelopeError {
	MessageDecodingErr(MessageInError),
	ProtocolErr(SignalProtocolError),
	PreKeyBundleErr(String),
	PreKeyNoAddress,
	UnknownEnvelopeType(Envelope),
	ProfileError(String),
	InvalidSenderKeyDistributionMessage(String),
	GroupError(GroupsError)
}
impl std::fmt::Display for HandleEnvelopeError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			HandleEnvelopeError::MessageDecodingErr(e) => write!(f, "Hit a message-decoding error while attempting to handle an envelope: {:?}", e),
			HandleEnvelopeError::ProtocolErr(e) => write!(f, "Encountered a protocol error while attempting to decode an envelope: {:?}", e),
			HandleEnvelopeError::PreKeyBundleErr(e) => write!(f, "Error occurred while handling a pre-key bundle: {}", e),
			HandleEnvelopeError::PreKeyNoAddress => write!(f, "No peer / foreign address on a pre-key bundle message!"),
			HandleEnvelopeError::UnknownEnvelopeType(e) => write!(f, "Received an \"Unknown\" message type from Websocket! Envelope is: {:?}",e),
			HandleEnvelopeError::ProfileError(e) => write!(f, "Attempted to retrieve profile information in the process of handling an envelope, but a problem was encountered: {:?}",e),
			HandleEnvelopeError::InvalidSenderKeyDistributionMessage(e) => write!(f, "Could not deserialize a Sender Key Distribution Message: {:?}",e),
			HandleEnvelopeError::GroupError(e) => write!(f, "Issue encountered while handing an inbound Group message: {:?}",e),
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
impl From<GroupsError> for HandleEnvelopeError {
	fn from(val: GroupsError) -> Self {
		HandleEnvelopeError::GroupError(val)
	}
}

/// Any error encountered while receiving and decoding a message.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
// TODO(Diana): Figure out something here?
pub enum ReceiveError {
	NetSpecific(String),
	SendErr(String),
	InError(MessageInError),
	HandlerError(HandleEnvelopeError),
	StoreStateError(String),
	ReconnectErr(String),
	AttachmentErr(String),
	DeserializeErr(String),
	UnknownWebsocketTy,
}

impl std::fmt::Display for ReceiveError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Self::NetSpecific(e) => {
				write!(f, "Net manager implementation produced an error: {:?}", e)
			}
			Self::SendErr(e) => write!(
				f,
				"Net manager errored while attempting to send a response: {:?}",
				e
			),
			Self::InError(e) => write!(f, "Unable to decode or decrypt message: {:?}", e),
			Self::StoreStateError(e) => {
				write!(f, "Unable to store state after receiving message: {:?}", e)
			}
			Self::ReconnectErr(e) => {
				write!(f, "Error while attempting to reconnect websocket: {:?}", e)
			}
			Self::AttachmentErr(e) => {
				write!(f, "Error while attempting to retrieve attachment: {:?}", e)
			}
			Self::UnknownWebsocketTy => write!(f, "Websocket message type is Unknown!"),
			Self::DeserializeErr(e) => write!(f, "Failed to deserialize incoming message: {:?}", e),
			Self::HandlerError(e) => write!(
				f,
				"Failed to handle incoming envelope inside receive loop: {:?}",
				e
			),
		}
	}
}

impl std::error::Error for ReceiveError {}

impl From<MessageInError> for ReceiveError {
	fn from(val: MessageInError) -> Self {
		Self::InError(val)
	}
}
impl From<HandleEnvelopeError> for ReceiveError {
	fn from(val: HandleEnvelopeError) -> Self {
		if let HandleEnvelopeError::MessageDecodingErr(e) = val {
			Self::InError(e)
		} else {
			Self::HandlerError(val)
		}
	}
}

#[derive(Debug)]
pub enum SetProfileError {
	NonSuccessResponse(http::Response<String>),
	AvatarTokenError(String),
	CouldNotEncryptAvatar(AttachmentEncryptError),
	UploadAvatarFailed(AttachmentUploadError),
}

impl std::fmt::Display for SetProfileError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			SetProfileError::NonSuccessResponse(e) => write!(f, "Got a failure code in response to our set-profile request. The response was: {:?}.", e),
			SetProfileError::AvatarTokenError(e) => write!(f, "Unable to deserialize avatar upload token: {}.", e),
			SetProfileError::CouldNotEncryptAvatar(e) => write!(f, "Failed to encrypt avatar for upload: {:?}.", e),
			SetProfileError::UploadAvatarFailed(e) => write!(f, "Failed to upload avatar: {:?}.", e),
		}
	}
}
impl std::error::Error for SetProfileError {}

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
	/// * `local_phone_number` - This node's Signal user account's phone number. TODO: Refactor this to allow accounts with no phone numbers when Signal fully implements usernames.
	/// * `config` - Configuration for various properties of this Signal app.
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
		info!("Start of ensure_peer_loaded() at {}", generate_timestamp());
		debug!(
			"Attempting to ensure all necessary information is present for peer {}",
			recipient_addr
		);

		let recipient_addr = self
			.context
			.peer_cache
			.complete_address(recipient_addr)
			.or_else(|| Some(recipient_addr.clone()))
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
		info!("End of ensure_peer_loaded() at {}", generate_timestamp());
		Ok(())
	}

	async fn send_message_inner(
		&mut self,
		recipient_addr: &AuxinAddress,
		message_list: &AuxinMessageList,
	) -> std::result::Result<(Timestamp, http::Response<Vec<u8>>), SendMessageError> {
		// Can we do sealed sender messages here?
		let sealed_sender: bool = self
			.context
			.peer_cache
			.get(recipient_addr)
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
			.generate_messages_to_all_devices(&mut self.context, mode, None, &mut self.rng, timestamp)
			.await
			.map_err(|e| SendMessageError::MessageBuildErr(format!("{:?}", e)))?;

		let request: http::Request<Vec<u8>> = outgoing_push_list
			.build_http_request(recipient_addr, mode, &mut self.context, &mut self.rng)
			.map_err(|e| SendMessageError::CannotMakeMessageRequest(format!("{:?}", e)))?;
		let message_response = self
			.http_client
			.request(request)
			.map_err(|e| SendMessageError::CannotMakeMessageRequest(format!("{:?}", e)))
			.await?;
		Ok((timestamp, message_response))
	}

	/// Send a message (any type of message) to a fellow Signal user.
	/// Returns the timestamp at which this message was generated.
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
			.or_else(|| Some(recipient_addr.clone()))
			.unwrap();

		// Will this be the last message in a session that we send?
		let end_session = message.content.end_session;

		//Make sure we know everything about this user that we need to.
		self.ensure_peer_loaded(&recipient_addr)
			.await
			.map_err(|e| SendMessageError::PeerStoreIssue(format!("{:?}", e)))?;

		let recipient_addr = self
			.context
			.peer_cache
			.complete_address(&recipient_addr)
			.or_else(|| Some(recipient_addr.clone()))
			.unwrap();

		let message_list = AuxinMessageList {
			messages: vec![message],
			remote_address: recipient_addr.clone(),
		};

		//Actually send it!
		let (mut sent_timestamp, message_response) = self
			.send_message_inner(&recipient_addr, &message_list)
			.await?;

		//Parse the response
		let message_response_str = String::from_utf8(message_response.body().to_vec()).unwrap();
		debug!(
			"Got response to attempt to send message: {:?} {}",
			message_response, message_response_str
		);
		if !message_response.status().is_success() {
			let mismatch_list: MismatchedDevices =
				match serde_json::from_str(message_response_str.as_str()) {
					Ok(v) => v,
					Err(_) => {
						// Return a regular error if this isn't a MismatchedDevices
						return Err(SendMessageError::CannotMakeMessageRequest(format!(
							"Response to send message: {:?} {}",
							message_response, message_response_str
						)));
						//Otherwise, this is a device mismatch issue
					}
				};
			//For logging purposes, figure out what we have on file.
			let existing_list = {
				let peer = self.context.peer_cache.get(&recipient_addr).unwrap();
				peer.device_ids_used.clone()
			};
			//And then delete the thing we just copied. Clear it out so we only get new state.
			self.context
				.peer_cache
				.get_mut(&recipient_addr)
				.unwrap()
				.device_ids_used
				.clear();
			self.context
				.peer_cache
				.get_mut(&recipient_addr)
				.unwrap()
				.registration_ids
				.clear();

			//Get new device list
			info!("Mismatched device list for {}. We have {:?}, and the server sent: {:?}. Attempting to fetch devices...", &recipient_addr, &existing_list, &mismatch_list );
			self.fill_peer_info(&recipient_addr)
				.await
				.map_err(|e| SendMessageError::PeerStoreIssue(format!("{:?}", e)))?;
			info!(
				"Attempting to re-send message with original timestamp {}",
				&sent_timestamp
			);
			let (new_timestamp, message_response) = self
				.send_message_inner(&recipient_addr, &message_list)
				.await?;
			sent_timestamp = new_timestamp;

			// Only retry once.
			if !message_response.status().is_success() {
				return Err(SendMessageError::AttemptTwoFail(format!(
					"{:?}",
					message_response
				)));
			}
			//Otherwise, we should be good.
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
		Ok(sent_timestamp)
	}

	/// Get a sender certificate for ourselves from Signal's web API, so that we can send sealed_sender messages properly.
	/// Retrieved through a request to https://textsecure-service.whispersystems.org/v1/certificate/delivery
	pub async fn retrieve_sender_cert(&mut self) -> Result<()> {
		info!(
			"Start of retrieve_sender_cert() at {}",
			generate_timestamp()
		);
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

		info!("End of retrieve_sender_cert() at {}", generate_timestamp());
		Ok(())
	}

	/// Retrieves and fills in core information about a peer that is necessary to send a message to them.
	///
	/// # Arguments
	///
	/// * `recipient_addr` - The address of the peer whose information we are retrieving.
	pub async fn fill_peer_info(&mut self, recipient_addr: &AuxinAddress) -> Result<()> {
		info!("Start of fill_peer_info() at {}", generate_timestamp());
		let signal_ctx = self.context.get_signal_ctx().get();

		// Once you get here, retrieve_and_store_peer() should have already been called,
		// so we should definitely have a UUID.
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
			let recipient = self.context.peer_cache.get_mut(recipient_addr).unwrap();

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
		info!("End of fill_peer_info() at {}", generate_timestamp());
		Ok(())
	}

	/// Retrieve information for a peer for whom we have a phone number, but no UUID.
	///
	/// # Arguments
	///
	/// * `recipient_addr` - The address of the peer whose contact information we are retrieving.
	pub async fn retrieve_and_store_peer(&mut self, recipient_phone: &E164) -> Result<()> {
		info!(
			"Start of retrieve_and_store_peer() at {}",
			generate_timestamp()
		);
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

		info!(
			"End of retrieve_and_store_peer() at {}",
			generate_timestamp()
		);
		Ok(())
	}

	/// Retrieve public keys and device IDs of a peer.
	/// NOTE: You can get rate-limited on this method VERY easily. Try not to invoke it too often.
	///
	/// # Arguments
	///
	/// * `uuid` - The address of the peer whose information we are retrieving. A UUID is required for this.
	pub async fn request_peer_info(&self, uuid: &Uuid) -> Result<PeerInfoReply> {
		info!("Start of request_peer_info() at {}", generate_timestamp());
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
		info!("End of request_peer_info() at {}", generate_timestamp());
		Ok(info)
	}

	pub async fn upgrade_auth_header(&mut self) -> Result<String> {
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
		Ok(upgraded_auth_header)
	}

	/// Used to retrieve the UUID for a peer when we have their phone number and not their UUID.
	/// This gets an attestation and uses that to make a request to Signal's discovery service,
	/// which uses Intel SGX to ensure privacy for your contact list.
	///
	/// # Arguments
	///
	/// * `recipient_phone` - The phone number we are attempting to retrieve a corresponding UUID for.
	pub async fn make_discovery_request(&mut self, recipient_phone: &E164) -> Result<Uuid> {
		info!(
			"Start of make_discovery_request() at {}",
			generate_timestamp()
		);
		//Get upgraded auth for discovery / directory.
		let upgraded_auth_header = self.upgrade_auth_header().await?;
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
		//println!("{:?}", cookies);

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
		//println!("{:?}", resulting_cookie_string);

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
		info!(
			"End of make_discovery_request() at {}",
			generate_timestamp()
		);
		Ok(uuid)
	}

	/// Attempts to get a peer's profile information (without decrypting) from Signal's web API.
	///
	/// # Arguments
	///
	/// * `recipient` - The address of the peer we're attempting to get an encrypted profile for.
	pub async fn retrieve_profile(
		&mut self,
		recipient_addr: &AuxinAddress,
	) -> std::result::Result<ProfileResponse, ProfileRetrievalError> {
		info!("Start of retrieve_profile() at {}", generate_timestamp());
		self.ensure_peer_loaded(recipient_addr).await.map_err(|e| {
			ProfileRetrievalError::ErrPeer(recipient_addr.clone(), format!("{:?}", e))
		})?;
		//We may have just grabbed the UUID in ensure_peer_loaded() above, make sure we have a usable address.
		let recipient = self
			.context
			.peer_cache
			.complete_address(recipient_addr)
			.unwrap_or_else(|| recipient_addr.clone());

		if let Some(peer) = self.context.peer_cache.get(&recipient) {
			if let Some(profile_key) = &peer.profile_key {
				let mut profile_key_bytes: [u8; PROFILE_KEY_LEN] = [0; PROFILE_KEY_LEN];
				let temp_bytes = base64::decode(profile_key).map_err(|e| {
					ProfileRetrievalError::EncodingError(recipient.clone(), format!("{:?}", e))
				})?;
				profile_key_bytes.copy_from_slice(&(temp_bytes)[0..PROFILE_KEY_LEN]);

				let uuid = recipient.get_uuid().map_err(|e| {
					ProfileRetrievalError::NoUuid(recipient.clone(), format!("{:?}", e))
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
					ProfileRetrievalError::EncodingError(recipient.clone(), format!("{:?}", e))
				})?;
				let version_string = String::from_utf8_lossy(&version_bytes);

				let get_path = format!(
					"https://textsecure-service.whispersystems.org/v1/profile/{}/{}/{}",
					uuid, version_string, encoded_request
				);

				let unidentified_access = self
					.context
					.get_unidentified_access_for(&recipient, &mut self.rng)
					.map_err(|e| {
						ProfileRetrievalError::UnidentifiedAccess(
							recipient.clone(),
							format!("{:?}", e),
						)
					})?;
				let unidentified_access = base64::encode(unidentified_access);
				let req = common_http_headers(
					http::Method::GET,
					&get_path,
					&self.context.identity.make_auth_header(),
				)
				.map_err(|e| {
					ProfileRetrievalError::EncodingError(recipient.clone(), format!("{:?}", e))
				})?
				.header("Unidentified-Access-Key", unidentified_access)
				.body(Vec::default())
				.map_err(|e| {
					ProfileRetrievalError::EncodingError(recipient.clone(), format!("{:?}", e))
				})?;
				debug!("Requesting profile key credential with {:?}", req);
				let response = self.http_client.request(req).await.map_err(|e| {
					ProfileRetrievalError::EncodingError(recipient.clone(), format!("{:?}", e))
				})?;

				let response_str = String::from_utf8(response.body().to_vec()).map_err(|e| {
					ProfileRetrievalError::DecodingError(recipient.clone(), format!("{:?}", e))
				})?;

				debug!("Provided profile response string was: {}", &response_str);

				let profile_response = serde_json::from_str(&response_str).map_err(|e| {
					ProfileRetrievalError::DecodingError(recipient.clone(), format!("{:?}", e))
				})?;

				info!("End of retrieve_profile() at {}", generate_timestamp());

				Ok(profile_response)
			} else {
				Err(ProfileRetrievalError::NoProfileKey(recipient.clone()))
			}
		} else {
			Err(ProfileRetrievalError::NoPeer(recipient.clone()))
		}
	}

	/// Get Signal profile information for the specified known peer. This peer must have a profile key known
	/// to us already (i.e. messages already received). Unlike retrieve_profile() (which this method calls
	/// internally), this message should decrypt the profile and also cache the profile when appropriate.
	///
	/// # Arguments
	///
	/// * `peer_address` - The address of the peer we're attempting to get Signal profile data for.
	pub async fn get_and_decrypt_profile(
		&mut self,
		peer_address: &AuxinAddress,
	) -> std::result::Result<PeerProfile, ProfileRetrievalError> {
		info!(
			"Start of get_and_decrypt_profile() at {}",
			generate_timestamp()
		);
		let response = self.retrieve_profile(peer_address).await?;

		//We may have just grabbed the UUID in ensure_peer_loaded() inside retrieve_profile(), make sure we have a usable address.
		let peer_address = self
			.context
			.peer_cache
			.complete_address(peer_address)
			.unwrap_or_else(|| peer_address.clone());

		//Set up cipher
		let profile_key = self
			.context
			.peer_cache
			.get(&peer_address)
			.ok_or_else(|| ProfileRetrievalError::NoPeer(peer_address.clone()))?
			.profile_key
			.as_ref()
			.ok_or_else(|| ProfileRetrievalError::NoProfileKey(peer_address.clone()))?;

		let mut profile_key_bytes: [u8; PROFILE_KEY_LEN] = [0; PROFILE_KEY_LEN];
		let temp_bytes = base64::decode(profile_key).map_err(|e| {
			ProfileRetrievalError::EncodingError(peer_address.clone(), format!("{:?}", e))
		})?;
		profile_key_bytes.copy_from_slice(&(temp_bytes)[0..PROFILE_KEY_LEN]);

		let profile_key = zkgroup::profiles::ProfileKey::create(profile_key_bytes);
		let profile_cipher = ProfileCipher::from(profile_key);

		// Start decrypting fields

		let (given_name, family_name) = match response.name {
			Some(b64_name) => {
				let name_bytes = base64::decode(b64_name).map_err(|e| {
					ProfileRetrievalError::DecodingError(peer_address.clone(), format!("{:?}", e))
				})?;
				let decrypted_name = profile_cipher.decrypt_name(&name_bytes).map_err(|e| {
					ProfileRetrievalError::DecryptingError(peer_address.clone(), format!("{:?}", e))
				})?;
				match decrypted_name {
					Some(name) => (Some(name.given_name), name.family_name),
					None => (None, None),
				}
			}
			None => (None, None),
		};

		let about = match response.about {
			Some(b64_about) => {
				let about_bytes = base64::decode(b64_about).map_err(|e| {
					ProfileRetrievalError::DecodingError(peer_address.clone(), format!("{:?}", e))
				})?;
				let decrypted_about = profile_cipher.decrypt_about(about_bytes).map_err(|e| {
					ProfileRetrievalError::DecryptingError(peer_address.clone(), format!("{:?}", e))
				})?;
				Some(decrypted_about)
			}
			None => None,
		};

		let about_emoji = match response.about_emoji {
			Some(b64_emoji) => {
				let emoji_bytes = base64::decode(b64_emoji).map_err(|e| {
					ProfileRetrievalError::DecodingError(peer_address.clone(), format!("{:?}", e))
				})?;
				let decrypted = profile_cipher.decrypt_about(emoji_bytes).map_err(|e| {
					ProfileRetrievalError::DecryptingError(peer_address.clone(), format!("{:?}", e))
				})?;
				Some(decrypted)
			}
			None => None,
		};

		// No decrypting needed here but let's take a look at the unidentified access mode and the capabilities.

		let unidentified_access_mode = match (
			response.unrestricted_unidentified_access,
			response.unidentified_access.is_some(),
		) {
			(true, _) => UnidentifiedAccessMode::UNRESTRICTED,
			(false, true) => UnidentifiedAccessMode::ENABLED,
			(false, false) => UnidentifiedAccessMode::DISABLED,
		};

		let mut capabilities: Vec<String> = Vec::default();
		if response.capabilities.gv1_migration {
			capabilities.push("gv1-migration".to_string());
		}
		if response.capabilities.gv2 {
			capabilities.push("gv2".to_string());
		}
		if response.capabilities.announcement_group {
			capabilities.push("announcementGroup".to_string());
		}
		if response.capabilities.sender_key {
			capabilities.push("senderKey".to_string());
		}

		//TODO: Code to support Signal's new (beta) "username" feature will be needed here.

		// Structure profile so we can both store it and return it.
		let result = PeerProfile {
			last_update_timestamp: generate_timestamp(),
			given_name,
			family_name,
			about,
			about_emoji,
			unidentified_access_mode,
			capabilities,
		};

		debug!(
			"Saving newly-received profile for {:?} with last updated timestamp {}",
			&peer_address, result.last_update_timestamp,
		);
		// self.retrieve_profile() *necessarily* ensured we have a peer profile made for this peer.
		// Assume one is present and update accordingly.
		self.context
			.peer_cache
			.get_mut(&peer_address)
			.unwrap()
			.profile = Some(result.clone());

		info!(
			"End of get_and_decrypt_profile() at {}",
			generate_timestamp()
		);
		Ok(result)
	}

	/// Attempts to get a SignalPay address / MobileCoin public address.
	///
	/// # Arguments
	///
	/// * `recipient` - The address of the peer we're attempting to get a payment address for.
	pub async fn retrieve_payment_address(
		&mut self,
		recipient_addr: &AuxinAddress,
	) -> std::result::Result<auxin_protos::PaymentAddress, PaymentAddressRetrievalError> {
		info!(
			"Start of retrieve_payment_address() at {}",
			generate_timestamp()
		);
		let response_structure = self.retrieve_profile(recipient_addr).await?;

		//We may have just grabbed the UUID in ensure_peer_loaded() inside retrieve_profile(), make sure we have a usable address.
		let recipient = self
			.context
			.peer_cache
			.complete_address(recipient_addr)
			.unwrap_or_else(|| recipient_addr.clone());

		if let Some(address_b64) = &response_structure.payment_address {
			// Retrieve profile key
			let profile_key = self
				.context
				.peer_cache
				.get(&recipient)
				.ok_or_else(|| {
					PaymentAddressRetrievalError::CouldntGetProfile(ProfileRetrievalError::NoPeer(
						recipient.clone(),
					))
				})?
				.profile_key
				.as_ref()
				.ok_or_else(|| {
					PaymentAddressRetrievalError::CouldntGetProfile(
						ProfileRetrievalError::NoProfileKey(recipient.clone()),
					)
				})?;
			// Decode it
			let mut profile_key_bytes: [u8; PROFILE_KEY_LEN] = [0; PROFILE_KEY_LEN];
			let temp_bytes = base64::decode(profile_key).map_err(|e| {
				ProfileRetrievalError::EncodingError(recipient.clone(), format!("{:?}", e))
			})?;
			profile_key_bytes.copy_from_slice(&(temp_bytes)[0..PROFILE_KEY_LEN]);

			//Put it in an actually usable struct.
			let key = aes_gcm::Key::from_slice(&profile_key_bytes);
			let cipher = Aes256Gcm::new(key);

			let payment_address_bytes = base64::decode(&address_b64).map_err(|e| {
				PaymentAddressRetrievalError::DecodingError(recipient.clone(), format!("{:?}", e))
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
				PaymentAddressRetrievalError::DecryptingError(recipient.clone(), format!("{:?}", e))
			})?;

			// 4 bits len - - 32 bit (signed?) integer describing buffer length.
			// This unwrap should never be hit, but if it is at least it wont silently truncate.
			let max_length = i32::try_from(decryption_result.len() - 4).unwrap();
			let mut tag_bytes: [u8; 4] = [0; 4];
			tag_bytes.copy_from_slice(&decryption_result[0..4]);
			let length = i32::from_le_bytes(tag_bytes);
			assert!(length < max_length);
			assert!(length > 0);

			let length = length as usize;
			let mut content_bytes: Vec<u8> = vec![0; length];

			// 4 bytes for length - offset by that. Get "length" bytes after the length tag itself.
			// The rest is padding.
			content_bytes.copy_from_slice(&decryption_result[4..(length + 4)]);

			let fixed_buf = fix_protobuf_buf(&content_bytes).map_err(|e| {
				PaymentAddressRetrievalError::DecodingError(recipient.clone(), format!("{:?}", e))
			})?;
			let mut reader = protobuf::CodedInputStream::from_bytes(&fixed_buf);
			let payment_address: auxin_protos::PaymentAddress =
				reader.read_message().map_err(|e| {
					PaymentAddressRetrievalError::DecodingError(
						recipient.clone(),
						format!("{:?}", e),
					)
				})?;
			info!(
				"End of retrieve_payment_address() at {}",
				generate_timestamp()
			);
			return Ok(payment_address);
		};
		Err(PaymentAddressRetrievalError::NoPaymentAddressForUser(
			recipient,
		))
	}

	/// Download an attachment from Signal's CDN.
	///
	/// # Arguments
	///
	/// * `attachment` - A SignalService attachment pointer,
	/// containing all information required to retrieve and decrypt this attachment. .
	pub async fn retrieve_attachment(
		&self,
		attachment: &AttachmentPointer,
	) -> std::result::Result<EncryptedAttachment, AttachmentDownloadError> {
		let mut cdn_addresses = HashMap::default();
		cdn_addresses.insert(0, SIGNAL_CDN.to_string());
		cdn_addresses.insert(2, SIGNAL_CDN_2.to_string());
		download::retrieve_attachment(attachment.clone(), self.http_client.clone(), cdn_addresses)
			.await
	}

	/// Retrieve a pre-upload token that you can use to upload an attachment to Signal's CDN.
	/// Note that no information about what we're going to upload is required - this just generates
	/// an ID that we can then turn around and use for an upload
	pub async fn request_attachment_upload_id(
		&self,
	) -> std::result::Result<AttachmentUploadToken, AttachmentUploadError> {
		let auth = self.context.identity.make_auth_header();
		attachment::upload::request_attachment_token(
			("Authorization", auth.as_str()),
			self.http_client.clone(),
		)
		.await
	}

	/// Retrieve a pre-upload token that you can use to upload an avatar to Signal's CDN.
	/// Note that no information about what we're going to upload is required - this just generates
	/// an ID that we can then turn around and use for an upload
	pub async fn request_avatar_upload_id(
		&self,
	) -> std::result::Result<PreUploadToken, AttachmentUploadError> {
		let auth = self.context.identity.make_auth_header();
		attachment::upload::request_avatar_upload_token(
			("Authorization", auth.as_str()),
			self.http_client.clone(),
		)
		.await
	}

	/// Upload an attachment to Signal's CDN.
	///
	/// # Arguments
	///
	/// * `upload_attributes` - The pre-upload token retrieved via request_attachment_upload_id().
	/// * `attachment` - An attachment which has been encrypted by auxin::attachment::upload::encrypt_attachment()
	pub async fn upload_attachment(
		&self,
		upload_attributes: &AttachmentUploadToken,
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
		info!(
			"Start of record_ids_from_message() at {}",
			generate_timestamp()
		);
		let completed_addr = self
			.context
			.peer_cache
			.complete_address(&message.remote_address.address)
			.unwrap_or_else(|| message.remote_address.address.clone());
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
		info!(
			"End of record_ids_from_message() at {}",
			generate_timestamp()
		);
		Ok(())
	}

	/// Handle an incoming message, process it from a Signal-protocol websocket message.
	/// This automatically sends a receipt notifying the sender that we have received this message.
	///
	/// Note that this does NOT send a WebSocketMessage response to the server - that layer of the
	/// protocol is not handled by Auxin App. If you are writing a message receiver loop, please
	/// ensure that you also acknowledge messages inside the Websocket channel properly.
	///
	/// Returns the decoded message.
	///
	/// Returns `Ok(None)` (and logs a warning) on recoverable error.
	///
	/// # Arguments
	///
	/// * `msg` - A WebSocketMessage polled from Signal's websocket API
	/// (wss://textsecure-service.whispersystems.org/v1/websocket/).
	/// This is the "WebSocketMessage" protocol buffer struct as defined in websocket.proto
	pub async fn receive_and_acknowledge(
		&mut self,
		msg: &auxin_protos::WebSocketMessage,
	) -> std::result::Result<Option<MessageIn>, ReceiveError> {
		info!(
			"Start of receive_and_acknowledge() at {}",
			generate_timestamp()
		);
		let msg_maybe = self.receive_decode(msg).await?;

		// See if we need to send a receipt.
		if let Some(msg_ok) = &msg_maybe {
			if msg_ok.needs_receipt() {
				let receipt = msg_ok.generate_receipt(auxin_protos::ReceiptMessage_Type::DELIVERY);
				self.send_message(&msg_ok.remote_address.address, receipt)
					.await
					.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;
			}
		}
		info!(
			"End of receive_and_acknowledge() at {}",
			generate_timestamp()
		);
		Ok(msg_maybe)
	}

	/// Handle an incoming message, process it from a Signal-protocol websocket message.
	/// Updates ratchet key state accordingly.
	///
	/// Returns the decoded message.
	///
	/// Returns `Ok(None)` (and logs a warning) on recoverable error.
	///
	/// # Arguments
	///
	/// * `msg` - A WebSocketMessage polled from Signal's websocket API (wss://textsecure-service.whispersystems.org/v1/websocket/).
	/// This is the "WebSocketMessage" protocol buffer struct as defined in websocket.proto
	pub async fn receive_decode(
		&mut self,
		msg: &auxin_protos::WebSocketMessage,
	) -> std::result::Result<Option<MessageIn>, ReceiveError> {
		trace!("Receive_decode on {:?}", msg);
		match msg.get_field_type() {
			auxin_protos::WebSocketMessage_Type::UNKNOWN => Err(ReceiveError::UnknownWebsocketTy),
			auxin_protos::WebSocketMessage_Type::REQUEST => {
				let req = msg.get_request();

				let envelope = read_envelope_from_bin(req.get_body())
					.map_err(|e| ReceiveError::DeserializeErr(format!("{:?}", e)))?;

				let maybe_address = address_from_envelope(&envelope);
				let maybe_a_message = self.handle_inbound_envelope(envelope).await;

				// Done this way to ensure invalid messages are still acknowledged, to clear them from the queue.
				let msg = match maybe_a_message {
					Err(HandleEnvelopeError::MessageDecodingErr(
						MessageInError::ProtocolError(e),
					)) => {
						warn!("Message from address {:?} failed to decrypt - ignoring error and continuing to receive messages to clear out prior bad state. Error was: {:?}", maybe_address, e);
						None
					}
					Err(HandleEnvelopeError::ProtocolErr(e)) => {
						warn!("Message from address {:?} failed to decrypt - ignoring error and continuing to receive messages to clear out prior bad state. Error was: {:?}", maybe_address, e);
						None
					}
					Err(HandleEnvelopeError::MessageDecodingErr(
						MessageInError::DecodingProblem(e),
					)) => {
						warn!("Message from address {:?} failed to decode (bad envelope?) - ignoring error and continuing to receive messages to clear out prior bad state. Error was: {:?}", maybe_address, e);
						None
					}
					Err(e) => {
						error!(
							"Error encountered in receive_decode() on a message from address {:?}",
							maybe_address
						);
						return Err(e.into());
					}
					Ok(m) => m,
					//It's okay that this can return None, because next() will continue to poll on a None return from this method, and try getting more messages.
					//"None" returns from handle_inbound_envelope() imply messages meant for the protocol rather than the end-user.
				};
				if let Some(msg) = &msg {
					//Save session.
					self.state_manager
						.save_peer_sessions(&msg.remote_address.address, &self.context)
						.map_err(|e| ReceiveError::StoreStateError(format!("{:?}", e)))?;
				}
				Ok(msg)
			}
			auxin_protos::WebSocketMessage_Type::RESPONSE => {
				let res = msg.get_response();
				warn!("WebSocket response message received: {:?}", res);
				Ok(None)
			}
		}
	}

	/// Examine a Signal Service "Content" message, checking to see if it has a sender key distribution message and processing that incoming message if there is one. 
	async fn check_sender_key_distribution(&mut self, content: &auxin_protos::Content, remote_address: &AuxinDeviceAddress) -> std::result::Result<(), HandleEnvelopeError> { 
		if content.has_senderKeyDistributionMessage() { 
			let sender_key_distribution_message_bytes = content.get_senderKeyDistributionMessage();
			let sender_key_distribution_message = SenderKeyDistributionMessage::try_from(sender_key_distribution_message_bytes)
				.map_err(|e| HandleEnvelopeError::InvalidSenderKeyDistributionMessage(format!("{:?}", e)) )?;

			let ctx = self.context.get_signal_ctx().clone();
			debug!("Got a SenderKeyDistributionMessage: {:?}. GroupsV2 support is a work in progress so this doesn't do anything yet.", &sender_key_distribution_message);
			//let protocol_address = result.remote_address.uuid_protocol_address().unwrap();
			let sender_key_name = SenderKeyName{sender: remote_address.clone(), distribution_id: sender_key_distribution_message.distribution_id()?};

			//Update or initialize ongoing group session.
			process_sender_key(&mut self.context.sender_key_store, sender_key_name, sender_key_distribution_message, &ctx).await?;
		}
		Ok(())
	}

	/// Examine a Signal Service "DataMessage", checking to see if it has groups or Groupsv2 metadata. 
	/// Note: This one doesn't check Sender Keys. Try check_sender_key_distribution() or the wrapper
	/// for this function and that one, update_groups_from()
	async fn inner_update_groups_from(&mut self, data_message: &auxin_protos::DataMessage, remote_address: &AuxinDeviceAddress) -> std::result::Result<(), GroupsError> { 
		// GroupsV1
		if data_message.has_group() {
			let group_context = data_message.get_group();
			debug!("Got GroupContext from {:?}, containing: {:?}", remote_address, group_context);
		}
		// GroupsV2
		if data_message.has_groupV2() {
			let group_context = data_message.get_groupV2();
			debug!("Got GroupContextV2 from {:?}, containing: {:?}", remote_address, group_context);
			// In testing, group_context.master_key is 32 bytes (I counted, hah)
			if group_context.get_masterKey().len() == 32 { 
				let mut master_key_bytes: [u8;32] = [0;32]; 
				master_key_bytes.copy_from_slice(&group_context.get_masterKey()[0..32]);
				let master_key = GroupMasterKey::new(master_key_bytes.clone());
				let group_secret_params = GroupSecretParams::derive_from_master_key(master_key);
				//let group_public_params = secret_params.get_public_params();
				// In zkgroup::constants.rs: pub const GROUP_IDENTIFIER_LEN: usize = 32;

				let group_id: GroupIdV2 = group_secret_params.get_group_identifier();
				//let group_ops = GroupOperations::new(group_secret_params);

				let mut credentials_manager = InMemoryCredentialsCache::new();

				let mut group_manager = GroupsManager::new(&mut self.http_client,
				&mut credentials_manager,
				&self.context.identity,
				get_server_public_params());

				let our_uuid = self.context.identity.address.get_uuid().unwrap().clone();

				let auth = group_manager.get_authorization_for_today(our_uuid.clone(), group_secret_params.clone()).await?;
				let group = group_manager.get_group(group_secret_params, &auth).await?;

				// Get a list of group members without ourselves.
				let group_members: Vec<GroupMemberInfo> = get_group_members_without(&group, &our_uuid).iter().map(|m| m.as_ref().unwrap().clone() ).collect();
				
				// "Store profile keys for known peers" step. 
				for group_member in group_members.iter() { 
					if let Some(pk) = group_member.profile_key {
						if let Some(peer) = self.context.peer_cache.get_by_uuid_mut(&group_member.id) { 
							// I have manually checked - these are valid profile keys for the users, not some key-derivation thing. 
							peer.profile_key = Some(base64::encode(&pk.get_bytes()));
						}
					}
				}
				let group_id_b64 = base64::encode(&group_id);
				debug!("Group ID when converted to base64 is: {}", group_id_b64);

				let master_key_b64 = base64::encode(&master_key_bytes);
				debug!("Master key when converted to base64 is: {}", master_key_b64);
				/*
				// "Import new peers" step.
				for group_member in group_members.iter() {
					let peer_address = AuxinAddress::Uuid(group_member.id.clone());
					if !self.context.peer_cache.has_peer(&peer_address) {
						let new_id = self.context.peer_cache.last_id + 1;
						self.context.peer_cache.last_id = new_id;
						let record = PeerRecord {
							id: new_id,
							number: None,
							uuid: Some(group_member.id.clone()),
							profile_key: group_member.profile_key.map(|pk| base64::encode(&pk.get_bytes())),
							profile_key_credential: None,
							contact: None,
							profile: None,
							device_ids_used: HashSet::default(),
							registration_ids: HashMap::default(),
							identity: None,
						};
						self.context.peer_cache.push(record);
						self.fill_peer_info(&peer_address).await
							.map_err(|e| GroupsError::FillPeerInfoError(format!("{:?}", e)))?;
					}
				}

				// "Make sure we know their names now that we probably have a profile key" step
				for group_member in group_members.iter() { 
					let peer_address = AuxinAddress::Uuid(group_member.id.clone());
					if let Some(_pk) = group_member.profile_key {
						let profile_response = self.get_and_decrypt_profile(&peer_address).await
							.map_err(|e| GroupsError::FillPeerInfoError(format!("{:?}", e)))?;
						if let Some(peer) = self.context.peer_cache.get_by_uuid_mut(&group_member.id) {
							peer.profile = Some(profile_response);
						}
					}
				}*/
			}
			else {
				return Err(GroupsError::InvalidMasterKeyLength(group_context.get_masterKey().len() as usize));
			}
		}
		Ok(())
	}
	async fn update_groups_from(&mut self, content: &auxin_protos::Content, remote_address: &AuxinDeviceAddress) -> std::result::Result<(), HandleEnvelopeError> { 
		if content.has_senderKeyDistributionMessage() { 
			debug!("Got SenderKeyDistributionMessage from {:?}", remote_address);
			self.check_sender_key_distribution(content, remote_address).await?;
		}
		if content.has_dataMessage() { 
			let data_message = content.get_dataMessage(); 
			self.inner_update_groups_from(data_message, remote_address).await?;
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
				info!(
					"Start of decrypting a standard ciphertext message at {}",
					generate_timestamp()
				);
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

				//Handle possible sender key distribution message.
				if let Some(content) = &result.content.source {
					self.update_groups_from(content, &result.remote_address).await?;
				}

				info!(
					"End of decrypting a standard ciphertext message at {}",
					generate_timestamp()
				);
				//Return
				result
			})),
			auxin_protos::Envelope_Type::KEY_EXCHANGE => todo!(),
			auxin_protos::Envelope_Type::PREKEY_BUNDLE => {
				info!(
					"Start of decrypting a prekey bundle message at {}",
					generate_timestamp()
				);
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
						.unwrap_or_else(|| a.address.clone());
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
				MessageIn::update_key_and_address_from(
					&content,
					&remote_address.address,
					&mut self.context,
				)?;

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

				info!(
					"End of decrypting a prekey bundle message at {}",
					generate_timestamp()
				);
				Ok(Some(result))
			}
			auxin_protos::Envelope_Type::RECEIPT => Ok(Some({
				info!(
					"Start of decoding a receipt message at {}",
					generate_timestamp()
				);
				let result = MessageIn::from_receipt(envelope, &mut self.context).await?;

				//Receipts cannot be end-session messages.
				self.record_ids_from_message(&result).await.unwrap();
				info!(
					"End of decoding a receipt message at {}",
					generate_timestamp()
				);

				result
			})),
			auxin_protos::Envelope_Type::UNIDENTIFIED_SENDER => Ok(Some({
				info!(
					"Start of decrypting a sealed-sender message at {}",
					generate_timestamp()
				);
				let result = MessageIn::from_sealed_sender(envelope, &mut self.context).await?;

				self.record_ids_from_message(&result).await.unwrap();

				if result.content.end_session {
					info!("Got an END_SESSION flag from a peer, clearing out their session state. Message was: {:?}", &result);
					self.clear_session(&result.remote_address.address)
						.await
						.unwrap(); // TODO: Proper error handling on clear_session();
				}


				//Handle possible sender key distribution message.
				if let Some(content) = &result.content.source {
					self.update_groups_from(content, &result.remote_address).await?;
				}

				info!(
					"End of decrypting a sealed-sender message at {}",
					generate_timestamp()
				);
				//Return
				result
			})),
			auxin_protos::Envelope_Type::PLAINTEXT_CONTENT => todo!(),
			auxin_protos::Envelope_Type::SENDER_KEY => { 
				todo!("GroupsV2 support is a work in progress. Received a SenderKey message, but we cannot use it yet.")
			},
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
		let peer_record = match self.context.peer_cache.get(peer_addr) {
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
			.save_peer_sessions(peer_addr, &self.context)?;

		Ok(())
	}

	pub async fn save_entire_context(&mut self) -> Result<()> {
		self.state_manager.save_entire_context(&self.context)
	}

	/// Upload the provided ProfileSetRequest (as generated by build_set_profile_request()) to Signal's web API
	pub async fn upload_profile(
		&mut self,
		base_url: &str,
		cdn_url: &str,
		mut parameters: ProfileConfig,
		avatar_buf: Option<Vec<u8>>,
	) -> crate::Result<http::Response<String>> {
		let has_avatar: bool = if avatar_buf.is_none() {
			//Make sure we don't tell the server "Hey I'm going to upload an avatar"
			//when there is no avatar to upload.
			parameters.avatar_file = None;
			false
		} else {
			parameters.avatar_file.is_some()
		};

		let maybe_avatar_filename = parameters.avatar_file.clone();

		let profile_ciphertext =
			build_set_profile_request(parameters, &self.context.identity, &mut self.rng)?;

		let path = format!("{}/v1/profile", base_url);

		let json_request = serde_json::to_vec(&profile_ciphertext)?;

		let auth = self.context.identity.make_auth_header();

		let mut req = common_http_headers(http::Method::PUT, &path, &auth)?;
		req = req.header("Content-Type", "application/json; charset=utf-8");
		req = req.header("Content-Length", json_request.len());
		let req = req.body(json_request)?;

		debug!("Sending request to update profile: {:?}", &req);

		let res = self.http_client.request(req).await?;
		let (parts, body) = res.into_parts();
		let body_string = match String::from_utf8(body.clone()) {
			Ok(st) => st,
			Err(_) => hex::encode(&body),
		};
		let resulting_response = http::Response::from_parts(parts, body_string);

		debug!(
			"In response to our attempt to set our profile, the server sent: {:?}",
			&resulting_response
		);

		//Error out if we got a non-success response code.
		if !resulting_response.status().is_success() {
			return Err(Box::new(SetProfileError::NonSuccessResponse(
				resulting_response,
			)));
		}

		//Now do avatar-related behavior.
		if has_avatar {
			//Now do the avatar
			let body_string = resulting_response.body();

			let upload_token: PreUploadToken = serde_json::from_str(body_string)
				.map_err(|e| SetProfileError::AvatarTokenError(format!("{:?}", e)))?;
			// if has_avatar is true, there is a parameters.avatar_file, so we can unwrap here.
			let raw_path = maybe_avatar_filename.unwrap();
			//Make sure we have a specific file and not a path here.
			let filename = if raw_path.contains('/') {
				//Cannot use std::Path here as that will break on wasm.
				let resl = raw_path.rsplit_once('/').unwrap().1;

				sanitize_filename::sanitize(resl)
			} else {
				sanitize_filename::sanitize(raw_path)
			};

			let attachment = avatar_buf.unwrap();
			debug!(
				"Attempting to upload {}-byte avatar with file name {}.",
				attachment.len(),
				&filename
			);

			let profile_key =
				zkgroup::profiles::ProfileKey::create(self.context.identity.profile_key);
			// Encrypt with profile key
			let profile_cipher = ProfileCipher::from(profile_key);
			let encrypted_avatar_bytes = profile_cipher.encrypt_avatar(attachment).unwrap();
			debug!(
				"Produced avatar ciphertext which is {:?} bytes long.",
				encrypted_avatar_bytes.len()
			);

			//Figure out a mime type
			let mime_name = content_type_from_filename(&filename);
			//If this doesn't end in a / for some reason, make sure it does now.
			let mut url = cdn_url.to_string();
			if !cdn_url.ends_with('/') {
				url.push('/');
			}
			let cdn_url = url.as_str();
			debug!(
				"Guessed file type as {} and upload address as {}",
				&mime_name, &cdn_url
			);
			//Actually upload the avatar
			let auth = self.context.identity.make_auth_header();
			let res = attachment::upload::upload_to_cdn(
				&upload_token,
				encrypted_avatar_bytes,
				mime_name.as_str(),
				("Authorization", auth.as_str()),
				self.http_client.clone(),
				cdn_url,
			)
			.await
			.map_err(SetProfileError::UploadAvatarFailed)?;

			//We should be all done, now just try to make some legible log output
			let (parts, body) = res.into_parts();
			let body_string = match String::from_utf8(body.clone()) {
				Ok(st) => st,
				Err(_) => hex::encode(&body),
			};
			let avatar_response = http::Response::from_parts(parts, body_string);
			debug!(
				"Our attempt to upload avatar file {} yielded the response {:?}",
				filename, avatar_response
			);

			//let attachment_identifier = AttachmentId::cdnKey(upload_token.key.clone());
			//let attachment_pointer = make_attachment_pointer(&attachment_identifier, &prepared_attachment).await?;
		}
		Ok(resulting_response)
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
