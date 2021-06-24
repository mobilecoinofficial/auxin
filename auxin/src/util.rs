use std::error::Error;
use lazy_static::lazy_static;
use libsignal_protocol::PublicKey;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Makes the protocol buffers sent by Signal's web API compatible with the Rust "protobuf" library.
/// The messages Signal sends us just start with raw data right away (binary blob). However, the rust implementation of 
/// "Protobuf" expects each "Message" type to start with a Varin64 specifying the length of the message.
/// So, this function uses buf.len() to add a proper length varint so protobuf can deserialize this message.
fn fix_protobuf_buf(buf: &Vec<u8>) -> Result< Vec<u8> > {
	let mut new_buf: Vec<u8> = Vec::new();
	// It is expecting this to start with "Len".
	let mut writer = protobuf::CodedOutputStream::vec(&mut new_buf);
	writer.write_raw_varint64(buf.len() as u64)?;
	writer.flush()?;
	new_buf.append(&mut buf.clone());
	Ok(new_buf)
}

lazy_static!{
    /// Trust root for all "Sealed Sender" messages.
    pub static ref SEALED_TRUST_ROOT : PublicKey = PublicKey::deserialize(base64::decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF").unwrap().as_slice()).unwrap();
}