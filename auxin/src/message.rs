use crate::{address::AuxinDeviceAddress, util::Result};
use custom_error::custom_error;
use serde::{Serialize, Deserialize};

pub type Timestamp = u64;

pub mod envelope_types { 
	custom_error!{ pub EnvelopeTypeError
		InvalidTypeId{attempted_value:i128} = "Attempted to decode {attempted_value} as an Envelope Type. Valid envelope types are 0 through 6.",
	}
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};
	use num_enum::IntoPrimitive;
	use custom_error::custom_error;
	use std::convert::TryFrom;

	pub const UNKNOWN : u8             = 0;
	pub const CIPHERTEXT : u8          = 1;
	pub const KEY_EXCHANGE : u8        = 2;
	pub const PREKEY_BUNDLE : u8       = 3;
	pub const RECEIPT : u8             = 5;
	pub const UNIDENTIFIED_SENDER : u8 = 6;

	pub const HIGHEST_VALUE : u8 = UNIDENTIFIED_SENDER;

	#[derive(Debug, Eq, PartialEq, IntoPrimitive, Copy, Clone)]
	#[repr(u8)]	
	pub enum EnvelopeType { 
		Unknown             = UNKNOWN,
		Ciphertext          = CIPHERTEXT,
		KeyExchange         = KEY_EXCHANGE,
		PreKeyBundle        = PREKEY_BUNDLE,
		Recipt              = RECEIPT,
		UnidentifiedSender  = UNIDENTIFIED_SENDER,
	}

	impl TryFrom<u8> for EnvelopeType {
		type Error = EnvelopeTypeError;

		fn try_from(value: u8) -> Result<Self, Self::Error> {
			match value { 
				UNKNOWN				=> Ok(EnvelopeType::Unknown),
				CIPHERTEXT			=> Ok(EnvelopeType::Ciphertext),
				KEY_EXCHANGE		=> Ok(EnvelopeType::KeyExchange),
				PREKEY_BUNDLE		=> Ok(EnvelopeType::PreKeyBundle),
				RECEIPT 			=> Ok(EnvelopeType::Recipt),
				UNIDENTIFIED_SENDER	=> Ok(EnvelopeType::UnidentifiedSender),
				_ => Err(EnvelopeTypeError::InvalidTypeId{attempted_value: value as i128})
			}
		}
	}

	impl TryFrom<u16> for EnvelopeType {
		type Error = EnvelopeTypeError;
		fn try_from(value: u16) -> Result<Self, Self::Error> {
			if value as u8 > HIGHEST_VALUE {
				Err(EnvelopeTypeError::InvalidTypeId{attempted_value: value as i128})
			} else {
				Ok(EnvelopeType::try_from(value as u8)?)
			}
		}
	}
	impl TryFrom<u32> for EnvelopeType {
		type Error = EnvelopeTypeError;
		fn try_from(value: u32) -> Result<Self, Self::Error> {
			if value as u8 > HIGHEST_VALUE {
				Err(EnvelopeTypeError::InvalidTypeId{attempted_value: value as i128})
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
                auxin_protos::Envelope_Type::UNIDENTIFIED_SENDER => EnvelopeType::UnidentifiedSender,
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
                EnvelopeType::UnidentifiedSender => auxin_protos::Envelope_Type::UNIDENTIFIED_SENDER,
            }
		}
    }

	impl TryFrom<u64> for EnvelopeType {
		type Error = EnvelopeTypeError;
		fn try_from(value: u64) -> Result<Self, Self::Error> {
			if value as u8 > HIGHEST_VALUE {
				Err(EnvelopeTypeError::InvalidTypeId{attempted_value: value as i128})
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
				    EnvelopeType::try_from(value).map_err(| _e | 
                        E::invalid_value(serde::de::Unexpected::Other(format!("{}", value).as_str() ), &"an integer between 0 and 6"))
                }

                fn visit_u16<E>(self, value: u16) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    EnvelopeType::try_from(value).map_err(| _e | 
                        E::invalid_value(serde::de::Unexpected::Other(format!("{}", value).as_str() ), &"an integer between 0 and 6"))
                }

                fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    EnvelopeType::try_from(value).map_err(| _e | 
                        E::invalid_value(serde::de::Unexpected::Other(format!("{}", value).as_str() ), &"an integer between 0 and 6"))
                }

                fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    EnvelopeType::try_from(value).map_err(| _e | 
                        E::invalid_value(serde::de::Unexpected::Other(format!("{}", value).as_str() ), &"an integer between 0 and 6"))
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
const PADDING_START_CHAR : u8 = 0x80;

custom_error!{ pub PaddingError
    PaddingStartNotFound = "Could not find the padding start character 0x80 in a buffer we attempted to un-pad.",
}

/// Used to pad the body of a message to 160 characters total (159 before encryption).
/// For example, this needs to be used on the serialized form of an auxin_protos::Content
/// before passing it as the message body to something like sealed_sender_encrypt().
pub fn pad_message_body(message: &[u8]) -> Vec<u8> {
	//Messages must be broken up into 160-byte chunks... 
	fn get_padded_message_length(unpadded_length: usize) -> usize { 
		let length_with_terminator = unpadded_length +1; 
		let mut message_chunk_count = length_with_terminator/160;
		if (length_with_terminator % 160) != 0 {
			message_chunk_count += 1;
		}
		
		return message_chunk_count * 160; 
	}
	// ...However, the cipher will add its own byte, so the output of this method must leave one byte worth of room. 
	let output_len = get_padded_message_length(message.len()+1)-1;
	let mut output: Vec<u8> = vec![0; output_len];
	assert_eq!(output.len(), output_len);

	output[..message.len()].clone_from_slice(message);
	//Add a special terminator character, signifying the end of this message and the start of padding. 
	output[message.len()] = PADDING_START_CHAR;

	return output; 
}

/// Remove padding from an inbound message. 
/// For example - you will need to use this on the "message" field of the sealed_sender_decrypt() function. 
pub fn remove_message_padding(message: &Vec<u8>) -> Result<Vec<u8>> {
	for (i, elem) in message.iter().enumerate() {
		//Only check the final chunk
		if (i + 160) >= message.len() { 
			//Did we find the padding? 
			//And also, is it the last character in the buffor (INCLUSIVE OR) is the next character 0? 
			//(Rust lazy-evaluates boolean expressions left-to-right, so we can get away wtih this)
			if (*elem == PADDING_START_CHAR) 
				&& (( (i+1) >= message.len() ) || (message[(i+1)] == 0))
			{
					
				return Ok(Vec::from(&message[..i]));
			}
		}
	}
	return Err(Box::new(PaddingError::PaddingStartNotFound));
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

/// Content we can send / receive over the network, represented abstractly.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    TextMessage(String),
    /// Takes a mode ("Delivered" to mean the inbox got it, "Read" to mean somebody saw it) 
    /// and one or more timestamps of the *messages we are acknowledging we received.*
    /// NOTE: Be VERY careful not to 
    ReceiptMessage(ReceiptMode, Timestamp),
    Other(auxin_protos::Content),
}

impl MessageContent {
    /// Construct an auxin_protos::Content out of this message.
    pub fn build_signal_content(&self, our_profile_key: &String, timestamp: Timestamp) -> Result<auxin_protos::Content> {
        match self {
            MessageContent::TextMessage(msg) => {
                let mut data_message = auxin_protos::DataMessage::default();
                data_message.set_body(msg.clone());
                data_message.set_timestamp(timestamp);
                let pk = base64::decode(our_profile_key.as_str())?;
                data_message.set_profileKey(pk);
                let _ = protobuf::Message::compute_size(&data_message);
            
                let mut content_message = auxin_protos::Content::default();
                content_message.set_dataMessage(data_message);
                let _ = protobuf::Message::compute_size(&content_message);

                Ok(content_message)
            },
            MessageContent::ReceiptMessage(_, _) => todo!(),
            MessageContent::Other(content) => Ok(content.clone()),
        }
    }
}

/// The abstract representation of a message we are sending or have received.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AuxinMessage {
    pub content: MessageContent,
    /// The address of the peer we are sending to / receiving from.
    pub remote_address: AuxinDeviceAddress,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AuxinMessageList {
    pub messages: Vec<AuxinMessage>, 
    pub remote_address: AuxinDeviceAddress,
    pub direction: MessageDirection,
}