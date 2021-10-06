use std::{
	convert::{Infallible, TryFrom},
	str::FromStr,
};

use crate::{
	address::{AuxinAddress, AuxinDeviceAddress},
	generate_timestamp, sealed_sender_trust_root,
	state::PeerStore,
	AuxinContext, ProfileKey, Result,
};
use auxin_protos::{AttachmentPointer, DataMessage_Quote, Envelope, Envelope_Type};
use custom_error::custom_error;
use libsignal_protocol::{
	message_decrypt, message_encrypt, sealed_sender_decrypt, sealed_sender_encrypt,
	CiphertextMessage, CiphertextMessageType, SessionStore, SignalMessage, SignalProtocolError,
};
use log::debug;
use protobuf::{CodedInputStream, CodedOutputStream};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type Timestamp = u64;

// CiphertextMessageType.PreKey goes to Envelope.Type.PREKEY_BUNDLE
// CiphertextMessageType.Whisper goes to Envelope.Type.CIPHERTEXT

pub mod envelope_types {
	custom_error! { pub EnvelopeTypeError
		InvalidTypeId{attempted_value:i128} = "Attempted to decode {attempted_value} as an Envelope Type. Valid envelope types are 0 through 6.",
	}
	use custom_error::custom_error;
	use num_enum::IntoPrimitive;
	use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
	use std::convert::TryFrom;

	pub const UNKNOWN: u8 = 0;
	pub const CIPHERTEXT: u8 = 1;
	pub const KEY_EXCHANGE: u8 = 2;
	pub const PREKEY_BUNDLE: u8 = 3;
	pub const RECEIPT: u8 = 5;
	pub const UNIDENTIFIED_SENDER: u8 = 6;
	pub const PLAINTEXT_CONTENT: u8 = 8;

	pub const HIGHEST_VALUE: u8 = UNIDENTIFIED_SENDER;

	#[derive(Debug, Eq, PartialEq, IntoPrimitive, Copy, Clone)]
	#[repr(u8)]
	pub enum EnvelopeType {
		Unknown = UNKNOWN,
		Ciphertext = CIPHERTEXT,
		KeyExchange = KEY_EXCHANGE,
		PreKeyBundle = PREKEY_BUNDLE,
		Recipt = RECEIPT,
		UnidentifiedSender = UNIDENTIFIED_SENDER,
		PlaintextContent = PLAINTEXT_CONTENT,
	}

	impl TryFrom<u8> for EnvelopeType {
		type Error = EnvelopeTypeError;

		fn try_from(value: u8) -> Result<Self, Self::Error> {
			match value {
				UNKNOWN => Ok(EnvelopeType::Unknown),
				CIPHERTEXT => Ok(EnvelopeType::Ciphertext),
				KEY_EXCHANGE => Ok(EnvelopeType::KeyExchange),
				PREKEY_BUNDLE => Ok(EnvelopeType::PreKeyBundle),
				RECEIPT => Ok(EnvelopeType::Recipt),
				UNIDENTIFIED_SENDER => Ok(EnvelopeType::UnidentifiedSender),
				PLAINTEXT_CONTENT => Ok(EnvelopeType::PlaintextContent),
				_ => Err(EnvelopeTypeError::InvalidTypeId {
					attempted_value: value as i128,
				}),
			}
		}
	}

	impl TryFrom<u16> for EnvelopeType {
		type Error = EnvelopeTypeError;
		fn try_from(value: u16) -> Result<Self, Self::Error> {
			if value as u8 > HIGHEST_VALUE {
				Err(EnvelopeTypeError::InvalidTypeId {
					attempted_value: value as i128,
				})
			} else {
				Ok(EnvelopeType::try_from(value as u8)?)
			}
		}
	}
	impl TryFrom<u32> for EnvelopeType {
		type Error = EnvelopeTypeError;
		fn try_from(value: u32) -> Result<Self, Self::Error> {
			if value as u8 > HIGHEST_VALUE {
				Err(EnvelopeTypeError::InvalidTypeId {
					attempted_value: value as i128,
				})
			} else {
				Ok(EnvelopeType::try_from(value as u8)?)
			}
		}
	}

	impl From<auxin_protos::Envelope_Type> for EnvelopeType {
		fn from(value: auxin_protos::Envelope_Type) -> Self {
			match value {
				auxin_protos::Envelope_Type::UNKNOWN => EnvelopeType::Unknown,
				auxin_protos::Envelope_Type::CIPHERTEXT => EnvelopeType::Ciphertext,
				auxin_protos::Envelope_Type::KEY_EXCHANGE => EnvelopeType::KeyExchange,
				auxin_protos::Envelope_Type::PREKEY_BUNDLE => EnvelopeType::PreKeyBundle,
				auxin_protos::Envelope_Type::RECEIPT => EnvelopeType::Recipt,
				auxin_protos::Envelope_Type::UNIDENTIFIED_SENDER => {
					EnvelopeType::UnidentifiedSender
				}
				auxin_protos::Envelope_Type::PLAINTEXT_CONTENT => EnvelopeType::PlaintextContent,
			}
		}
	}

	impl From<EnvelopeType> for auxin_protos::Envelope_Type {
		fn from(value: EnvelopeType) -> Self {
			match value {
				EnvelopeType::Unknown => auxin_protos::Envelope_Type::UNKNOWN,
				EnvelopeType::Ciphertext => auxin_protos::Envelope_Type::CIPHERTEXT,
				EnvelopeType::KeyExchange => auxin_protos::Envelope_Type::KEY_EXCHANGE,
				EnvelopeType::PreKeyBundle => auxin_protos::Envelope_Type::PREKEY_BUNDLE,
				EnvelopeType::Recipt => auxin_protos::Envelope_Type::RECEIPT,
				EnvelopeType::UnidentifiedSender => {
					auxin_protos::Envelope_Type::UNIDENTIFIED_SENDER
				}
				EnvelopeType::PlaintextContent => auxin_protos::Envelope_Type::PLAINTEXT_CONTENT,
			}
		}
	}

	impl TryFrom<u64> for EnvelopeType {
		type Error = EnvelopeTypeError;
		fn try_from(value: u64) -> Result<Self, Self::Error> {
			if value as u8 > HIGHEST_VALUE {
				Err(EnvelopeTypeError::InvalidTypeId {
					attempted_value: value as i128,
				})
			} else {
				Ok(EnvelopeType::try_from(value as u8)?)
			}
		}
	}
	impl Serialize for EnvelopeType {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			serializer.serialize_u8(u8::from(*self))
		}
	}
	impl<'de> Deserialize<'de> for EnvelopeType {
		fn deserialize<D>(deserializer: D) -> Result<EnvelopeType, D::Error>
		where
			D: Deserializer<'de>,
		{
			struct EnvelopeTypeVisitor;

			impl<'de> Visitor<'de> for EnvelopeTypeVisitor {
				type Value = EnvelopeType;

				fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
					formatter.write_str("an integer between 0 and 6")
				}

				fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
				where
					E: serde::de::Error,
				{
					EnvelopeType::try_from(value).map_err(|_e| {
						E::invalid_value(
							serde::de::Unexpected::Other(format!("{}", value).as_str()),
							&"an integer between 0 and 6",
						)
					})
				}

				fn visit_u16<E>(self, value: u16) -> Result<Self::Value, E>
				where
					E: serde::de::Error,
				{
					EnvelopeType::try_from(value).map_err(|_e| {
						E::invalid_value(
							serde::de::Unexpected::Other(format!("{}", value).as_str()),
							&"an integer between 0 and 6",
						)
					})
				}

				fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
				where
					E: serde::de::Error,
				{
					EnvelopeType::try_from(value).map_err(|_e| {
						E::invalid_value(
							serde::de::Unexpected::Other(format!("{}", value).as_str()),
							&"an integer between 0 and 6",
						)
					})
				}

				fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
				where
					E: serde::de::Error,
				{
					EnvelopeType::try_from(value).map_err(|_e| {
						E::invalid_value(
							serde::de::Unexpected::Other(format!("{}", value).as_str()),
							&"an integer between 0 and 6",
						)
					})
				}
			}

			deserializer.deserialize_u8(EnvelopeTypeVisitor)
		}
	}
}

/*----------------------------------------------------\\
||--- SERIALIZATION/DESERIALIZATION HELPER METHODS ---||
\\----------------------------------------------------*/

//128
const PADDING_START_CHAR: u8 = 0x80;

custom_error! { pub PaddingError
	PaddingStartNotFound = "Could not find the padding start character 0x80 in a buffer we attempted to un-pad.",
}

/// Used to pad the body of a message to 160 characters total (159 before encryption).
/// For example, this needs to be used on the serialized form of an auxin_protos::Content
/// before passing it as the message body to something like sealed_sender_encrypt().
pub fn pad_message_body(message: &[u8]) -> Vec<u8> {
	//Messages must be broken up into 160-byte chunks...
	fn get_padded_message_length(unpadded_length: usize) -> usize {
		let length_with_terminator = unpadded_length + 1;
		let mut message_chunk_count = length_with_terminator / 160;
		if (length_with_terminator % 160) != 0 {
			message_chunk_count += 1;
		}

		return message_chunk_count * 160;
	}
	// ...However, the cipher will add its own byte, so the output of this method must leave one byte worth of room.
	let output_len = get_padded_message_length(message.len() + 1) - 1;
	let mut output: Vec<u8> = vec![0; output_len];
	assert_eq!(output.len(), output_len);

	output[..message.len()].clone_from_slice(message);
	//Add a special terminator character, signifying the end of this message and the start of padding.
	output[message.len()] = PADDING_START_CHAR;

	return output;
}

/// Remove padding from an inbound message.
/// For example - you will need to use this on the "message" field of the sealed_sender_decrypt() function.
pub fn remove_message_padding(message: &Vec<u8>) -> std::result::Result<Vec<u8>, PaddingError> {
	for (i, elem) in message.iter().enumerate() {
		//Only check the final chunk
		if (i + 160) >= message.len() {
			//Did we find the padding?
			//And also, is it the last character in the buffor (INCLUSIVE OR) is the next character 0?
			//(Rust lazy-evaluates boolean expressions left-to-right, so we can get away wtih this)
			if (*elem == PADDING_START_CHAR)
				&& (((i + 1) >= message.len()) || (message[(i + 1)] == 0))
			{
				return Ok(Vec::from(&message[..i]));
			}
		}
	}
	return Err(PaddingError::PaddingStartNotFound);
}

/// Makes the protocol buffers sent by Signal's web API compatible with the Rust "protobuf" library.
/// The messages Signal sends us just start with raw data right away (binary blob). However, the rust implementation of
/// "Protobuf" expects each "Message" type to start with a Varin64 specifying the length of the message.
/// So, this function uses buf.len() to add a proper length varint so protobuf can deserialize this message.
pub fn fix_protobuf_buf(buf: &Vec<u8>) -> Result<Vec<u8>> {
	let mut new_buf: Vec<u8> = Vec::new();
	// It is expecting this to start with "Len".
	let mut writer = protobuf::CodedOutputStream::vec(&mut new_buf);
	writer.write_raw_varint64(buf.len() as u64)?;
	writer.flush()?;
	new_buf.append(&mut buf.clone());
	Ok(new_buf)
}

/// (Try to) read a raw byte buffer as a Signal Websocketmessage protobuf.
pub fn read_wsmessage_from_bin(buf: &[u8]) -> Result<auxin_protos::WebSocketMessage> {
	let new_buf = fix_protobuf_buf(&Vec::from(buf))?;
	let mut reader = protobuf::CodedInputStream::from_bytes(new_buf.as_slice());
	Ok(reader.read_message()?)
}

/*----------------------------------------------------------------------------\\
||--- INTERMEDIARY MESSAGE TYPES (USED TO GENERATE SIGNAL-COMPATIBLE JSON) ---||
\\----------------------------------------------------------------------------*/

//This is actually just a subset of protos::signalservice::Envelope! The more you know.
/// A signle message put in a correct form to send to the server.
/// Needs to be put into a OutgoingPushMessageList to be useful.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutgoingPushMessage {
	/// Corresponds to envelope_types::EnvelopeType as well as an auxin_protos::Envelope_Type
	#[serde(rename = "type")]
	pub envelope_type: u8,
	#[serde(rename = "destinationDeviceId")]
	pub destination_device_id: u32,
	#[serde(rename = "destinationRegistrationId")]
	pub destination_registration_id: u32,
	/// Base64-encoded cyphertext.
	pub content: String,
}

/// Used to send one or more messages via Signal.
/// Serialize this into json and put it into a 'PUT' request bound for https://textsecure-service.whispersystems.org/v1/messages/
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutgoingPushMessageList {
	#[serde(rename = "destination")]
	pub destination_uuid: String, //UUID
	pub timestamp: u64, //Timestamp is apparently a "long" which is an i32 in C, but a u64 should serialize to json the same.

	pub messages: Vec<OutgoingPushMessage>,
	pub online: bool,
}

impl OutgoingPushMessageList {
	pub fn build_http_request<Body, Rng>(
		&self,
		peer_address: &AuxinAddress,
		mode: MessageSendMode,
		context: &mut AuxinContext,
		rng: &mut Rng,
	) -> Result<http::Request<Body>>
	where
		Body: From<String>,
		Rng: RngCore + CryptoRng,
	{
		let json_message = serde_json::to_string(&self)?;

		let mut msg_path =
			String::from("https://textsecure-service.whispersystems.org/v1/messages/");
		msg_path.push_str(peer_address.get_uuid().unwrap().to_string().as_str());

		let mut req = crate::net::common_http_headers(
			http::Method::PUT,
			msg_path.as_str(),
			context.identity.make_auth_header().as_str(),
		)?;

		if mode == MessageSendMode::SealedSender {
			let unidentified_access_key =
				context.get_unidentified_access_for(&peer_address, rng)?;
			let unidentified_access_key = base64::encode(unidentified_access_key);
			debug!(
				"Attempting to send with unidentified access key {}",
				unidentified_access_key
			);
			req = req.header("Unidentified-Access-Key", unidentified_access_key);
		}
		req = req.header("Content-Type", "application/json; charset=utf-8");
		req = req.header("Content-Length", json_message.len());

		Ok(req.body(Body::from(json_message))?)
	}
}

/*----------------------------------------------------------------------------------------\\
||--- ABSTRACT AUXIN MESSAGE TYPES BUILT TO / DESERIALIZED FROM PROPER SIGNAL MESSAGES ---||
\\----------------------------------------------------------------------------------------*/

type ReceiptMode = auxin_protos::ReceiptMessage_Type;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum MessageDirection {
	/// A message to send from our node.
	Send,
	/// A message our node received.
	Received,
}

impl Default for MessageDirection {
	fn default() -> Self {
		MessageDirection::Received
	}
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum MessageSendMode {
	Standard,
	SealedSender,
}

impl Default for MessageSendMode {
	fn default() -> Self {
		MessageSendMode::Standard
	}
}

/// Content we can send / receive over the network, represented abstractly.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Default)]
pub struct MessageContent {
	pub text_message: Option<String>,
	/// Takes a mode ("Delivered" to mean the inbox got it, "Read" to mean somebody saw it)
	/// and one or more timestamps of the *messages we are acknowledging we received.*
	pub receipt_message: Option<(ReceiptMode, Vec<Timestamp>)>,
	pub quote: Option<DataMessage_Quote>,
	/// The Signal "content" this was deserialized from. Will only be None if this is an outgoing message.
	#[serde(skip_serializing)]
	pub source: Option<auxin_protos::Content>,
	pub attachments: Vec<AttachmentPointer>,
}

impl MessageContent {
	pub fn with_text(self, value: String) -> MessageContent {
		MessageContent {
			text_message: Some(value),
			receipt_message: self.receipt_message,
			quote: self.quote,
			source: self.source,
			attachments: self.attachments,
		}
	}

	/// Construct an auxin_protos::Content out of this message.
	pub fn build_signal_content(
		&self,
		our_profile_key: &String,
		timestamp: Timestamp,
	) -> Result<auxin_protos::Content> {
		// Did we create this message using a content message directly?
		if let Some(content) = &self.source {
			return Ok(content.clone());
		}

		// Otherwise, build from typical Auxin data.
		let mut result = auxin_protos::Content::default();

		let mut use_data_message: bool = false;
		let mut data_message = auxin_protos::DataMessage::default();
		data_message.set_timestamp(timestamp);
		let pk = base64::decode(our_profile_key.as_str())?;
		data_message.set_profileKey(pk);

		if let Some(msg) = &self.text_message {
			use_data_message = true;

			data_message.set_body(msg.clone());
			let _ = protobuf::Message::compute_size(&data_message);
		}
		//Add any attachments on this MessageOut to the DataMessage.
		for attachment in self.attachments.iter() { 
			use_data_message = true;
			data_message.attachments.push(attachment.clone());
		}

		if let Some((mode, acknowledging_timestamp)) = &self.receipt_message {
			let mut receipt_message = auxin_protos::ReceiptMessage::default();
			receipt_message.set_field_type(*mode);
			receipt_message.set_timestamp(acknowledging_timestamp.clone());

			let _ = protobuf::Message::compute_size(&receipt_message);
			result.set_receiptMessage(receipt_message);
		}

		if use_data_message {
			result.set_dataMessage(data_message);
			let _ = protobuf::Message::compute_size(&result);
		}

		Ok(result)
	}
}

/// The abstract representation of a message we are sending or receiving
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct MessageOut {
	pub content: MessageContent,
}

custom_error! { pub MessageOutError
	NoSenderCertificate{msg:String} = "Could not generate a sealed-sender message for {msg}: no \"Sender Certificate\" has been retrieved for this AuxinContext!",
}

impl MessageOut {
	pub async fn encrypt_message<Rng: RngCore + CryptoRng>(
		&self,
		address_to: &AuxinDeviceAddress,
		mode: MessageSendMode,
		context: &mut AuxinContext,
		rng: &mut Rng,
		timestamp: u64,
	) -> Result<OutgoingPushMessage> {
		let signal_ctx = context.get_signal_ctx().ctx.clone();
		//Make sure it has both UUID and phone number.
		let mut address_to = address_to.clone();
		address_to.address = context
			.peer_cache
			.complete_address(&address_to.address)
			.unwrap();
		//Get a valid protocol address with name=uuid
		let their_address = address_to.uuid_protocol_address()?;

		let sess = match context
			.session_store
			.load_session(&their_address, context.get_signal_ctx().ctx)
			.await
		{
			Ok(s) => s.unwrap(),
			Err(e) => return Err(Box::new(e)),
		};
		//Let's find their registration ID.
		let reg_id = sess.remote_registration_id()?;
		drop(sess);

		//Build our message.
		let mut serialized_message: Vec<u8> = Vec::default();
		let mut outstream = CodedOutputStream::vec(&mut serialized_message);

		let b64_profile_key = base64::encode(context.identity.profile_key);
		let content_message = self
			.content
			.build_signal_content(&b64_profile_key, timestamp)?;

		let sz = protobuf::Message::compute_size(&content_message);
		debug!("Estimated content message size: {}", sz);

		protobuf::Message::write_to_with_cached_sizes(&content_message, &mut outstream)?;
		outstream.flush()?;
		drop(outstream);
		debug!(
			"Length of message before padding: {}",
			serialized_message.len()
		);

		let our_message_bytes = pad_message_body(serialized_message.as_slice());
		debug!("Padded message length: {}", our_message_bytes.len());

		Ok(match mode {
			MessageSendMode::Standard => {
				//It is critically important that, at the very least, process_prekey_bundle (or something else that can start a session)
				//is called before this. In Auxin, process_prekey_bundle is called in AuxinApp.fill_peer_info()
				let cyphertext_message = message_encrypt(
					&our_message_bytes,
					&their_address,
					&mut context.session_store,
					&mut context.identity_store,
					signal_ctx,
				)
				.await?;
				let envelope_type = match cyphertext_message.message_type() {
					CiphertextMessageType::Whisper => envelope_types::CIPHERTEXT,
					CiphertextMessageType::PreKey => envelope_types::PREKEY_BUNDLE,
					_ => todo!(),
				};

				let content = base64::encode(cyphertext_message.serialize());
				debug!("Encoded to {} bytes of bas64", content.len());

				OutgoingPushMessage {
					envelope_type,
					destination_device_id: their_address.device_id(),
					destination_registration_id: reg_id,
					content: content,
				}
			}
			MessageSendMode::SealedSender => {
				//Make sure the sender certificate has actually been gotten already, or else throw an error.
				let sender_cert = context.sender_certificate.as_ref().ok_or(
					MessageOutError::NoSenderCertificate {
						msg: format!("{:?}", &self),
					},
				)?;

				//Encipher the content we just encoded.
				let cyphertext_message = sealed_sender_encrypt(
					&their_address,
					sender_cert,
					our_message_bytes.as_slice(),
					&mut context.session_store,
					&mut context.identity_store,
					signal_ctx,
					rng,
				)
				.await?;

				//Serialize our cyphertext.
				let content = base64::encode(cyphertext_message);

				debug!("Encoded to {} bytes of bas64", content.len());
				OutgoingPushMessage {
					envelope_type: envelope_types::UNIDENTIFIED_SENDER,
					destination_device_id: their_address.device_id(),
					destination_registration_id: reg_id,
					content,
				}
			}
		})
	}
}

#[derive(Debug)]
pub enum MessageInError {
	ProtocolError(SignalProtocolError),
	PaddingIssue(PaddingError),
	DecodingProblem(String),
	Infallible,
}
impl std::fmt::Display for MessageInError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			Self::ProtocolError(e) => write!(
				f,
				"The Signal Protocol encountered an error during encryption: {:?}",
				e
			),
			Self::PaddingIssue(e) => write!(f, "Unable to unpad incoming message: {:?}", e),
			Self::DecodingProblem(e) => write!(f, "Failed to decode incoming message: {:?}", e),
			Self::Infallible => write!(f, "This error should be impossible to see."),
		}
	}
}

impl std::error::Error for MessageInError {}

impl From<SignalProtocolError> for MessageInError {
	fn from(val: SignalProtocolError) -> Self {
		MessageInError::ProtocolError(val)
	}
}
impl From<Infallible> for MessageInError {
	fn from(_: Infallible) -> Self {
		MessageInError::Infallible
	}
}

/// Decrypts a sealed-sender envelope. Note that this also calls MessageIn::update_profile_key_from() if necessary.
pub async fn decrypt_unidentified_sender(
	envelope: &Envelope,
	context: &mut AuxinContext,
) -> std::result::Result<(MessageContent, AuxinDeviceAddress), MessageInError> {
	let signal_ctx = context.get_signal_ctx().ctx.clone();
	let decrypted = sealed_sender_decrypt(
		envelope.get_content(),
		&sealed_sender_trust_root(),
		generate_timestamp() as u64,
		context
			.identity
			.address
			.get_phone_number()
			.ok()
			.map(|s| s.clone()),
		context.identity.address.get_uuid().unwrap().to_string(),
		context.identity.address.device_id,
		&mut context.identity_store,
		&mut context.session_store,
		&mut context.pre_key_store,
		&mut context.signed_pre_key_store,
		signal_ctx,
	)
	.await
	.map_err(|e| MessageInError::ProtocolError(e))?;

	debug!("Length of decrypted message: {:?}", decrypted.message.len());

	let unpadded_message =
		remove_message_padding(&decrypted.message).map_err(|e| MessageInError::PaddingIssue(e))?;
	let fixed_buf = fix_protobuf_buf(&unpadded_message)
		.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?;

	let mut reader: CodedInputStream = CodedInputStream::from_bytes(fixed_buf.as_slice());
	let message: auxin_protos::Content = reader
		.read_message()
		.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?;

	let sender_uuid = Uuid::from_str(decrypted.sender_uuid().unwrap())
		.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?;
	let sender_e164 = decrypted
		.sender_e164()
		.ok()
		.flatten()
		.map(|s| s.to_string());

	let sender_address = match sender_e164 {
		Some(phone_number) => AuxinAddress::Both(phone_number, sender_uuid),
		None => AuxinAddress::Uuid(sender_uuid),
	};

	let remote_address = AuxinDeviceAddress {
		address: sender_address.clone(),
		device_id: decrypted.device_id,
	};

	MessageIn::update_profile_key_from(&message, &sender_address, context)?;

	debug!("Decrypted sealed sender message into: {:?}", &message);
	return Ok((
		MessageContent::try_from(message)
			.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?,
		remote_address,
	));
}

/// The abstract representation of a message we are receiving
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct MessageIn {
	pub content: MessageContent,
	/// The address of the peer we are receiving from.
	pub remote_address: AuxinDeviceAddress,
	pub timestamp: u64,
	/// Timestamp for when we got this message. Technically this is when it was *decoded*, not *received,* but it should be close enough for any metric we're worried about.
	pub timestamp_received: u64,
	pub server_guid: String,
}

impl MessageIn {
	/// Generate a receipt indicating that we received, or read, this message.
	pub fn generate_receipt(&self, mode: ReceiptMode) -> MessageOut {
		MessageOut {
			content: MessageContent {
				receipt_message: Some((mode, vec![self.timestamp])),
				text_message: None,
				source: None,
				quote: None,
				attachments: Vec::default(),
			},
		}
	}

	pub fn update_profile_key_from(
		content: &auxin_protos::Content,
		remote_address: &AuxinAddress,
		context: &mut AuxinContext,
	) -> std::result::Result<(), MessageInError> {
		let remote_address = context
			.peer_cache
			.complete_address(remote_address)
			.unwrap_or(remote_address.clone());

		if content.has_dataMessage() {
			if content.get_dataMessage().has_profileKey() {
				let mut pk: ProfileKey = ProfileKey::default();
				let pk_slice = content.get_dataMessage().get_profileKey();
				pk.copy_from_slice(pk_slice);

				let peer = context.peer_cache.get_mut(&remote_address);
				if let Some(peer) = peer {
					peer.profile_key = Some(base64::encode(pk));
				}
			}
		}
		Ok(())
	}

	pub async fn from_ciphertext_message<R: RngCore + CryptoRng>(
		envelope: Envelope,
		context: &mut AuxinContext,
		rng: &mut R,
	) -> std::result::Result<MessageIn, MessageInError> {
		assert_eq!(envelope.get_field_type(), Envelope_Type::CIPHERTEXT);
		debug!(
			"Decoding envelope from source: (E164: {}, UUID: {})",
			envelope.get_sourceE164(),
			envelope.get_sourceUuid()
		);
		// Build our remote address if this is not a sealed sender message.
		let remote_address = address_from_envelope(&envelope);
		let remote_address = remote_address.map(|a| {
			let mut new_addr = a.clone();
			new_addr.address = context
				.peer_cache
				.complete_address(&a.address)
				.unwrap_or(a.address.clone());
			new_addr
		});

		let remote_address = remote_address.unwrap();

		let signal_message = SignalMessage::try_from(envelope.get_content())?;
		let ciph = CiphertextMessage::SignalMessage(signal_message);
		let decrypted = decrypt_ciphertext(&ciph, context, rng, &remote_address).await?;

		Self::update_profile_key_from(&decrypted, &remote_address.address, context)?;

		Ok(MessageIn {
			content: MessageContent::try_from(decrypted)?,
			remote_address,
			timestamp: envelope.get_timestamp(),
			timestamp_received: generate_timestamp(), //Keep track of when we got it.
			server_guid: envelope.get_serverGuid().to_string(),
		})
	}

	pub async fn from_sealed_sender(
		envelope: Envelope,
		context: &mut AuxinContext
	) -> std::result::Result<MessageIn, MessageInError> {
		assert_eq!(envelope.get_field_type(), Envelope_Type::UNIDENTIFIED_SENDER);

		// Decrypt the sealed sender message and also unpad its data
		let (content, sender) = decrypt_unidentified_sender(&envelope, context).await?;

		Ok(MessageIn {
			content: MessageContent::try_from(content)?,
			remote_address: sender,
			timestamp: envelope.get_timestamp(),
			timestamp_received: generate_timestamp(), //Keep track of when we got it.
			server_guid: envelope.get_serverGuid().to_string(),
		})
	}

	pub async fn from_receipt(
		envelope: Envelope,
		context: &mut AuxinContext
	) -> std::result::Result<MessageIn, MessageInError> {
		assert_eq!(envelope.get_field_type(), Envelope_Type::RECEIPT);
		debug!(
			"Decoding envelope from source: (E164: {}, UUID: {})",
			envelope.get_sourceE164(),
			envelope.get_sourceUuid()
		);
		// Build our remote address if this is not a sealed sender message.
		let remote_address = address_from_envelope(&envelope);
		let remote_address = remote_address.map(|a| {
			let mut new_addr = a.clone();
			new_addr.address = context
				.peer_cache
				.complete_address(&a.address)
				.unwrap_or(a.address.clone());
			new_addr
		});

		let remote_address = remote_address.unwrap();
		Ok(MessageIn {
			content: MessageContent {
				receipt_message: Some((
					ReceiptMode::DELIVERY,
					vec![envelope.get_timestamp()],
				)),
				text_message: None,
				source: None,
				quote: None,
				attachments: Vec::default(),
			},
			remote_address: remote_address,
			timestamp: envelope.get_timestamp(),
			timestamp_received: generate_timestamp(), //Keep track of when we got it.
			server_guid: envelope.get_serverGuid().to_string(),
		})
	}

	/*pub async fn decode_envelope_bin<R: RngCore + CryptoRng>(
		bin: &[u8],
		context: &mut AuxinContext,
		rng: &mut R,
	) -> std::result::Result<Self, MessageInError> {
		let envelope = read_envelope_from_bin(bin)
			.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?;
		MessageIn::decode_envelope(envelope, context, rng).await
	}*/

	pub fn needs_receipt(&self) -> bool {
		// TODO: Evaluate if Receipt Messages are ever delivered alongside anything else in the same envelope.
		if let Some(_) = self.content.receipt_message {
			false
		} else {
			true
		}
	}
}

fn address_from_envelope(envelope: &Envelope) -> Option<AuxinDeviceAddress> {
	match envelope.has_sourceDevice() {
		true => {
			let source_device = envelope.get_sourceDevice();
			if envelope.has_sourceUuid() {
				Some(AuxinDeviceAddress {
					address: AuxinAddress::try_from(envelope.get_sourceUuid()).unwrap(),
					device_id: source_device,
				})
			} else if envelope.has_sourceE164() {
				Some(AuxinDeviceAddress {
					address: AuxinAddress::try_from(envelope.get_sourceE164()).unwrap(),
					device_id: source_device,
				})
			} else {
				None
			}
		}
		false => None,
	}
}

async fn decrypt_ciphertext<R: RngCore + CryptoRng>(
	ciphertext: &CiphertextMessage,
	context: &mut AuxinContext,
	rng: &mut R,
	remote_address: &AuxinDeviceAddress,
) -> std::result::Result<auxin_protos::Content, MessageInError> {
	let signal_ctx = context.get_signal_ctx().get();
	let decrypted = message_decrypt(
		ciphertext,
		&remote_address.uuid_protocol_address().unwrap(),
		&mut context.session_store,
		&mut context.identity_store,
		&mut context.pre_key_store,
		&mut context.signed_pre_key_store,
		rng,
		signal_ctx,
	)
	.await
	.map_err(|e| MessageInError::ProtocolError(e))?;

	let unpadded_message = remove_message_padding(&decrypted)
		.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?;
	let fixed_buf = fix_protobuf_buf(&unpadded_message)
		.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?;

	let mut reader: CodedInputStream = CodedInputStream::from_bytes(fixed_buf.as_slice());
	Ok(reader
		.read_message()
		.map_err(|e| MessageInError::DecodingProblem(format!("{:?}", e)))?)
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AuxinMessageList {
	pub messages: Vec<MessageOut>,
	pub remote_address: AuxinAddress,
}

impl AuxinMessageList {
	///Encrypts our_message string and builds an OutgoingPushMessage from it - One for each of remote_address's devices on file.
	pub async fn generate_messages_to_all_devices<Rng: RngCore + CryptoRng>(
		&self,
		context: &mut AuxinContext,
		mode: MessageSendMode,
		rng: &mut Rng,
		timestamp: u64,
	) -> Result<OutgoingPushMessageList> {
		let mut messages_to_send: Vec<OutgoingPushMessage> = Vec::default();
		//TODO: Better error handling here.
		let recipient = context
			.peer_cache
			.get(&self.remote_address)
			.unwrap()
			.clone();
		let address: AuxinAddress = (&recipient).into();

		for i in recipient.device_ids_used.iter() {
			let device_address = AuxinDeviceAddress {
				address: address.clone(),
				device_id: *i,
			};
			let protocol_address = device_address.uuid_protocol_address()?;
			debug!(
				"Send to ProtocolAddress {:?} owned by UUID {:?}",
				protocol_address,
				protocol_address.name()
			);

			for message_plaintext in self.messages.iter() {
				let message = message_plaintext
					.encrypt_message(
						&AuxinDeviceAddress {
							address: self.remote_address.clone(),
							device_id: *i,
						},
						mode,
						context,
						rng,
						timestamp,
					)
					.await?;

				messages_to_send.push(message);
			}
		}

		Ok(OutgoingPushMessageList {
			destination_uuid: address.get_uuid()?.to_string(),
			timestamp,
			messages: messages_to_send,
			online: context.report_as_online,
		})
	}
}

impl TryFrom<auxin_protos::Content> for MessageContent {
	type Error = MessageInError;

	fn try_from(value: auxin_protos::Content) -> std::result::Result<Self, Self::Error> {
		let mut result = MessageContent::default();
		if value.has_dataMessage() {
			let data_message = value.get_dataMessage();
			if data_message.has_body() {
				result.text_message = Some(data_message.get_body().to_string());
			}
			if data_message.attachments.len() > 0 {
				result.attachments =
					data_message.attachments.iter().map(|a| a.clone()).collect();
			}
		}
		if value.has_receiptMessage() {
			let receipt_message = value.get_receiptMessage();
			result.receipt_message = Some((
				receipt_message.get_field_type(),
				receipt_message.get_timestamp().to_vec(),
			));
		}

		result.source = Some(value);
		// TODO: More fine-grained results.
		return Ok(result);
	}
}
