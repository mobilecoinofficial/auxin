use std::ops::{Deref, DerefMut};

use address::AuxinDeviceAddress;
use libsignal_protocol::{IdentityKeyPair, IdentityKeyStore, PreKeyStore, SenderCertificate, SessionStore, SignedPreKeyStore};

pub mod util;
pub mod address;
pub mod net;
pub mod state;
pub mod message;


use rand::{CryptoRng};
//use serde::{Serialize, Deserialize};
use state::PeerRecordStructure;

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
pub struct Context {
    pub our_identity: LocalIdentity,
    pub our_sender_certificate: SenderCertificate,

    peer_cache: PeerRecordStructure,
    
    identity_keys: Box<dyn IdentityKeyStore>,
    sessions: Box<dyn SessionStore>,
    pre_keys: Box<dyn PreKeyStore>,
    signed_pre_keys: Box<dyn SignedPreKeyStore>,
    
    pub rng: Box<dyn CryptoRng>,
    pub config: AuxinConfig,
    pub signal_ctx: libsignal_protocol::Context,

    // The following booleans are used to track which fields had changes and need to be synced to storage.
    peer_cache_dirty: bool,
    identity_keys_dirty: bool,
    sessions_dirty: bool,
    pre_keys_dirty: bool,
    signed_pre_keys_dirty: bool,
}

impl Context {
    pub fn get_peer_cache(&self) -> &PeerRecordStructure{ 
        &self.peer_cache
    }
    pub fn get_peer_cache_mut(&mut self) -> &mut PeerRecordStructure{ 
        self.peer_cache_dirty = true; 
        &mut self.peer_cache
    }

    pub fn get_identity_keys<'a>(&'a self) -> &'a dyn IdentityKeyStore{ 
        self.identity_keys.deref()
    }
    pub fn get_identity_keys_mut<'a>(&'a mut self) -> &'a mut dyn IdentityKeyStore{ 
        self.identity_keys_dirty = true; 
        self.identity_keys.deref_mut()
    }

    pub fn get_sessions<'a>(&'a self) -> &'a dyn SessionStore{ 
        self.sessions.deref()
    }
    pub fn get_sessions_mut<'a>(&'a mut self) -> &'a mut dyn SessionStore{ 
        self.sessions_dirty = true;
        self.sessions.deref_mut()
    }

    pub fn get_pre_keys<'a>(&'a self) -> &'a dyn PreKeyStore{ 
        self.pre_keys.deref()
    }
    pub fn get_pre_keys_mut<'a>(&'a mut self) -> &'a mut dyn PreKeyStore{ 
        self.pre_keys_dirty = true;
        self.pre_keys.deref_mut()
    }

    pub fn get_signed_pre_keys<'a>(&'a self) -> &'a dyn SignedPreKeyStore{ 
        self.signed_pre_keys.deref()
    }
    pub fn get_signed_pre_keys_mut<'a>(&'a mut self) -> &'a mut dyn SignedPreKeyStore{ 
        self.signed_pre_keys_dirty = true;
        self.signed_pre_keys.deref_mut()
    }

    /// Has this field been changed (so it needs to be written out to storage)?
    pub fn is_peer_cache_dirty(&self) -> bool {
        self.peer_cache_dirty
    }
    /// Has this field been changed (so it needs to be written out to storage)?
    pub fn is_identity_keys_dirty(&self) -> bool {
        self.identity_keys_dirty
    }
    /// Has this field been changed (so it needs to be written out to storage)?
    pub fn is_sessions_dirty(&self) -> bool {
        self.sessions_dirty
    }
    /// Has this field been changed (so it needs to be written out to storage)?
    pub fn is_pre_keys_dirty(&self) -> bool {
        self.pre_keys_dirty
    }
    /// Has this field been changed (so it needs to be written out to storage)?
    pub fn is_signed_pre_keys_dirty(&self) -> bool {
        self.signed_pre_keys_dirty
    }

    pub fn set_peer_cache_dirty(&mut self, val: bool) {
        self.peer_cache_dirty = val;
    }
    pub fn set_identity_keys_dirty(&mut self, val: bool) {
        self.identity_keys_dirty = val;
    }
    pub fn set_sessions_dirty(&mut self, val: bool) {
        self.sessions_dirty = val;
    }
    pub fn set_pre_keys_dirty(&mut self, val: bool) {
        self.pre_keys_dirty = val;
    }
    pub fn set_signed_pre_keys_dirty(&mut self, val: bool) {
        self.signed_pre_keys_dirty = val;
    }

    pub fn mark_all_clean(&mut self) {
        self.peer_cache_dirty= true;
        self.identity_keys_dirty= true;
        self.sessions_dirty= true;
        self.pre_keys_dirty= true;
        self.signed_pre_keys_dirty= true;
    }


    pub fn new(our_identity: LocalIdentity, our_sender_certificate: SenderCertificate, peer_cache: PeerRecordStructure,
                identity_keys: Box<dyn IdentityKeyStore>, sessions: Box<dyn SessionStore>, 
                pre_keys: Box<dyn PreKeyStore>, signed_pre_keys: Box<dyn SignedPreKeyStore>, rng: Box<dyn CryptoRng>) -> Self {
        Context {
            our_identity,
            our_sender_certificate,

            peer_cache,
            
            identity_keys,
            sessions,
            pre_keys,
            signed_pre_keys,
            
            rng,
            config: AuxinConfig{ /* TODO */ },
            signal_ctx: libsignal_protocol::Context::default(),
        
            // The following booleans are used to track which 
            peer_cache_dirty: false,
            identity_keys_dirty: false,
            sessions_dirty: false,
            pre_keys_dirty: false,
            signed_pre_keys_dirty: false,
        }
    }
}