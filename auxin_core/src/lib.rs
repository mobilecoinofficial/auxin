// Copyright (c) 2021 MobileCoin Inc.
// Copyright (c) 2021 Emily Cultip

#![feature(string_remove_matches)]
#![feature(associated_type_bounds)]
#![feature(result_flattening)]
#![feature(hash_drain_filter)]
#![feature(drain_filter)]
#![deny(bare_trait_objects)]

//! Developer (and bot) friendly wrapper around the Signal protocol.

use address::AuxinAddress;
use attachment::{
	upload::{
		AttachmentEncryptError, AttachmentUploadError
	},
};

use auxin_protos::signal_service::Envelope;
use groups::{group_message::GroupEncryptionError, GroupApiError, GroupDecryptionError, GroupUtilsError};
use libsignal_protocol::{PublicKey, SignalProtocolError,};
use log::error;

use message::MessageInError;
use serde::{Deserialize, Serialize};
use std::{
	error::Error,
	fmt::Debug,
	time::{SystemTime, UNIX_EPOCH},
};
use zkgroup::ZkGroupError;

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

pub mod account;

/// Self-signing root cert for TLS connections to Signal's web API..
pub const SIGNAL_TLS_CERT: &str = include_str!("../data/whisper.pem");
/// Trust anchor for IAS - required to validate certificate chains for remote SGX attestation.
pub const IAS_TRUST_ANCHOR: &[u8] = include_bytes!("../data/ias.der");

use crate::{
	groups::GroupId,
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
/// (production / Signal environment)
pub fn sealed_sender_trust_root() -> PublicKey {
	PublicKey::deserialize(
		base64::decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF")
			.unwrap()
			.as_slice(),
	)
	.unwrap()
}

pub const DEFAULT_DEVICE_ID: u32 = 1;

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

#[derive(Debug)]
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
	ErrorSendingToGroup(SendGroupError),
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
			SendMessageError::ErrorSendingToGroup(e) => write!(f, "Error sending a message to a group: {:?}", e),
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

impl From<SendGroupError> for SendMessageError {
	fn from(value: SendGroupError) -> Self {
		SendMessageError::ErrorSendingToGroup(value)
	}
}

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
	CannotSave(String),
	NoGroupInfo(GroupId),
	ProtocolError(SignalProtocolError),
	ZkError(ZkGroupError),
	DecryptionError(GroupDecryptionError),
	ModifyMissingGroup(GroupId),
	UtilError(GroupUtilsError),
}
impl std::fmt::Display for GroupsError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			GroupsError::FillPeerInfoError(e) => write!(f, "There were unknown users in the group. While trying to retrieve device Ids for them, an error was encountered: {:?}", e),
			GroupsError::InvalidMasterKeyLength(size) => write!(f, "Invalid Master Key length on a Groups data message. The size was {} bytes and a Master Key is expected to be 32 bytes long.", size),
			GroupsError::ApiError(e) => write!(f, "Groups API error: {:?}.", e),
			GroupsError::CannotSave(e) => write!(f, "Unable to save group info: {:?}.", e),
			GroupsError::NoGroupInfo(id) => write!(f, "No group info on file for group {}, implying we have not joined that group or not recevied any messsages inside it.", id.to_base64()),
			GroupsError::ProtocolError(e) => write!(f, "Signal Protocol error in group operations: {:?}.", e),
			GroupsError::ZkError(e) => write!(f, "Error in Signal ZkGroups library: {:?}.", e),
			GroupsError::DecryptionError(e) => write!(f, "Failed to decrypt group properties: {:?}.", e),
			GroupsError::ModifyMissingGroup(id) => write!(f, "Attempted to modify our cache for group {}, but we have no cache for that group!", id.to_base64()),
			GroupsError::UtilError(e) => write!(f, "Group util error (most likely converting protobufs into usable structures): {:?}", e),
		}
	}
}
impl std::error::Error for GroupsError {}
impl From<GroupApiError> for GroupsError {
	fn from(val: GroupApiError) -> Self {
		GroupsError::ApiError(val)
	}
}
impl From<SignalProtocolError> for GroupsError {
	fn from(val: SignalProtocolError) -> Self {
		GroupsError::ProtocolError(val)
	}
}
impl From<ZkGroupError> for GroupsError {
	fn from(val: ZkGroupError) -> Self {
		GroupsError::ZkError(val)
	}
}
impl From<GroupDecryptionError> for GroupsError {
	fn from(val: GroupDecryptionError) -> Self {
		GroupsError::DecryptionError(val)
	}
}
impl From<GroupUtilsError> for GroupsError {
	fn from(val: GroupUtilsError) -> Self {
		GroupsError::UtilError(val)
	}
}

#[derive(thiserror::Error, Debug)]
pub enum SendGroupError {
	#[error("Group encryption error: {0:?}")]
	GroupEncryptError(#[from] GroupEncryptionError),
	#[error("Sender key / group state error: {0:?}")]
	GroupError(#[from] GroupsError),
	#[error("Signal protocol error encountered while attempting to send a group message: {0:?}")]
	ProtocolError(#[from] libsignal_protocol::SignalProtocolError),
	#[error("Failed to retrieve a sender certificate: {0}.")]
	SenderCertRetrieval(String),
	#[error("Only groups V2 is supported at present, legacy support for GroupsV1 is not yet implemented.")]
	Gv1NotSupported,
	#[error("Could not generage groups v2 message: {0}")]
	CouldNotGenerateMessage(String),
	#[error("Failed to get unidentified access key: {0}")]
	NoUnidentifiedAccess(String),
	#[error("Encountered an error building an HTTP message for the purposes of sending a group message: {0}")]
	TroubleBuildingHttp(String),
	#[error("Encountered an error trying to send a group message to Signal's web API: {0}")]
	NetworkError(String),
	#[error("Could not make sure a peer's profile was loaded for the purposes of group message sending: {0}")]
	PeerError(String),
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
	CouldntSaveSenderKey(String),
	GroupError(GroupsError),
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
			HandleEnvelopeError::CouldntSaveSenderKey(e) => write!(f, "Failed to store sender key: {:?}",e),
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