use address::AuxinDeviceAddress;
use libsignal_protocol::{IdentityKeyPair, PublicKey, SenderCertificate};
use std::error::Error;

pub mod address;
pub mod state;
pub mod message;


use rand::{CryptoRng};
//use serde::{Serialize, Deserialize};
use state::PeerStore;

pub const PROFILE_KEY_LEN: usize = 32;

pub type ProfileKey = [u8; PROFILE_KEY_LEN];

#[derive(Clone, Debug, Default)]
pub struct AuxinConfig { /* TODO */ }

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Makes the protocol buffers sent by Signal's web API compatible with the Rust "protobuf" library.
/// The messages Signal sends us just start with raw data right away (binary blob). However, the rust implementation of 
/// "Protobuf" expects each "Message" type to start with a Varin64 specifying the length of the message.
/// So, this function uses buf.len() to add a proper length varint so protobuf can deserialize this message.
fn _fix_protobuf_buf(buf: &Vec<u8>) -> Result< Vec<u8> > {
	let mut new_buf: Vec<u8> = Vec::new();
	// It is expecting this to start with "Len".
	let mut writer = protobuf::CodedOutputStream::vec(&mut new_buf);
	writer.write_raw_varint64(buf.len() as u64)?;
	writer.flush()?;
	new_buf.append(&mut buf.clone());
	Ok(new_buf)
}

/// Retrieves trust root for all "Sealed Sender" messages.
pub fn sealed_sender_trust_root() -> PublicKey {
    PublicKey::deserialize(base64::decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF").unwrap().as_slice()).unwrap()
}

#[derive(Clone)]
/// Basic information about the local Signal node. 
pub struct LocalIdentity {
    pub our_address: AuxinDeviceAddress,
    pub password: String,
    pub our_profile_key: ProfileKey,
    pub our_identity_keys: IdentityKeyPair,
    pub our_reg_id: u32,
}

#[allow(unused)] // TODO: Remove this after we can send/remove a message.
// This is the structure that an AuxinStateHandler builds and saves.
pub struct AuxinContext<Peers, ProtocolState, Rng> where Peers: PeerStore, ProtocolState: libsignal_protocol::ProtocolStore, Rng: CryptoRng {
    pub our_identity: LocalIdentity,
    pub our_sender_certificate: SenderCertificate,

    peer_cache: Peers,
    protocol_state: ProtocolState,
    pub rng: Rng,

    pub config: AuxinConfig,
    pub signal_ctx: libsignal_protocol::Context,
}

impl<Peers, ProtocolState, Rng> AuxinContext<Peers, ProtocolState, Rng> where Peers: PeerStore, ProtocolState: libsignal_protocol::ProtocolStore, Rng: CryptoRng {
    pub fn get_peer_cache<'a>(&'a self) -> &'a Peers { 
        &self.peer_cache
    }
    pub fn get_peer_cache_mut<'a>(&'a mut self) -> &'a mut Peers { 
        &mut self.peer_cache
    }

    pub fn get_protocol_state<'a>(&'a self) -> &'a ProtocolState { 
        &self.protocol_state
    }
    pub fn get_protocol_state_mut<'a>(&'a mut self) -> &'a mut ProtocolState {
        &mut self.protocol_state
    }

    pub fn new(our_identity: LocalIdentity, our_sender_certificate: SenderCertificate, 
                peer_cache: Peers, protocol_store: ProtocolState, config: AuxinConfig, rng: Rng) -> Self {
        AuxinContext {
            our_identity,
            our_sender_certificate,

            peer_cache,
            
            protocol_state: protocol_store,
            
            rng,
            config: config,
            signal_ctx: libsignal_protocol::Context::default(),
        }
    }
}