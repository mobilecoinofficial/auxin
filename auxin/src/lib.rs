use std::ops::{Deref, DerefMut};

use address::AuxinDeviceAddress;
use libsignal_protocol::{IdentityKeyPair, SenderCertificate};

pub mod util;
pub mod address;
pub mod net;
pub mod state;
pub mod message;


use rand::{CryptoRng};
//use serde::{Serialize, Deserialize};
use state::PeerStore;

pub const PROFILE_KEY_LEN: usize = 32;

pub type ProfileKey = [u8; PROFILE_KEY_LEN];

pub struct AuxinConfig { /* TODO */ }

#[derive(Clone)]
/// Basic information about the local Signal node. 
pub struct LocalIdentity {
    pub our_address: AuxinDeviceAddress,
    pub password: String,
    pub our_profile_key: ProfileKey,
    pub our_identity_keys: IdentityKeyPair,
}

#[allow(unused)] // TODO: Remove this after we can send/remove a message.
// This is the structure that an AuxinStateHandler builds and saves.
pub struct Context<Peers, ProtocolState, Rng> where Peers: PeerStore, ProtocolState: libsignal_protocol::ProtocolStore, Rng: CryptoRng {
    pub our_identity: LocalIdentity,
    pub our_sender_certificate: SenderCertificate,

    peer_cache: Peers,
    protocol_state: ProtocolState,
    pub rng: Rng,

    pub config: AuxinConfig,
    pub signal_ctx: libsignal_protocol::Context,
}

impl<Peers, ProtocolState, Rng> Context<Peers, ProtocolState, Rng> where Peers: PeerStore, ProtocolState: libsignal_protocol::ProtocolStore, Rng: CryptoRng {
    pub fn get_peer_cache<'a>(&'a self) -> &'a Peers{ 
        &self.peer_cache
    }
    pub fn get_peer_cache_mut<'a>(&'a mut self) -> &'a mut Peers{ 
        &mut self.peer_cache
    }

    pub fn get_protocol_state<'a>(&'a self) -> &'a ProtocolState{ 
        &self.protocol_state
    }
    pub fn get_protocol_state_mut<'a>(&'a mut self) -> &'a mut ProtocolState{ 
        &mut self.protocol_state
    }

    pub fn new(our_identity: LocalIdentity, our_sender_certificate: SenderCertificate, 
                peer_cache: Peers, protocol_store: ProtocolState, rng: Rng) -> Self {
        Context {
            our_identity,
            our_sender_certificate,

            peer_cache,
            
            protocol_state: protocol_store,
            
            rng,
            config: AuxinConfig{ /* TODO */ },
            signal_ctx: libsignal_protocol::Context::default(),
        }
    }
}