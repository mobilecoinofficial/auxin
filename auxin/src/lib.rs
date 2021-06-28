use address::{AuxinAddress, AuxinDeviceAddress};
use aes_gcm::{Nonce, aead::{Aead, NewAead}, aead::Payload};
use libsignal_protocol::{IdentityKeyPair, InMemIdentityKeyStore, InMemPreKeyStore, InMemSenderKeyStore, InMemSessionStore, InMemSignedPreKeyStore, PublicKey, SenderCertificate};
use log::debug;
use uuid::Uuid;
use std::{error::Error, time::{SystemTime, UNIX_EPOCH}};
use custom_error::custom_error;

pub mod address;
pub mod state;
pub mod net;
pub mod message;


use rand::{CryptoRng, Rng, RngCore};
//use serde::{Serialize, Deserialize};
use state::{PeerRecord, PeerRecordStructure, PeerStore, UnidentifiedAccessMode};

pub const PROFILE_KEY_LEN: usize = 32;

pub type ProfileKey = [u8; PROFILE_KEY_LEN];

#[derive(Clone, Debug, Default)]
pub struct AuxinConfig { /* TODO */ }

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn generate_timestamp() -> u64 {
	let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() as u64
}

/// Retrieves trust root for all "Sealed Sender" messages.
pub fn sealed_sender_trust_root() -> PublicKey {
    PublicKey::deserialize(base64::decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF").unwrap().as_slice()).unwrap()
}

pub const DEFAULT_DEVICE_ID: u32 = 1;

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
pub struct AuxinContext<Rng> where Rng: RngCore + CryptoRng {
    pub our_identity: LocalIdentity,
    pub our_sender_certificate: SenderCertificate,

    pub peer_cache: PeerRecordStructure,
    pub session_store: InMemSessionStore,
    pub pre_key_store: InMemPreKeyStore,
    pub signed_pre_key_store: InMemSignedPreKeyStore,
    pub identity_store: InMemIdentityKeyStore,
    pub sender_key_store: InMemSenderKeyStore,
    pub rng: Rng,

    pub config: AuxinConfig,
    pub signal_ctx: libsignal_protocol::Context,
    pub report_as_online: bool,
}

fn get_unidentified_access_for_key(profile_key: &String) -> Result<Vec<u8>> {
    let profile_key_bytes = base64::decode(profile_key)?;
    let profile_key = aes_gcm::Key::from_slice(profile_key_bytes.as_slice());
    let cipher = aes_gcm::Aes128Gcm::new(profile_key);
    //Libsignal-service-java enciphers 16 zeroes with a (re-used) nonce of 12 zeroes
    //to get this access key, unless I am horribly misreading it. 
    let zeroes: [u8; 16] = [0; 16];
    let nonce: [u8; 12] = [0; 12];
    let nonce = Nonce::from_slice(&nonce);

    let payload = Payload{msg: &zeroes, aad: b"" };

    Ok(cipher.encrypt(&nonce, payload)?)
}

fn get_unidentified_access_unrestricted<Rng: CryptoRng + RngCore>(rng: &mut Rng) -> Result<Vec<u8>> {
    let bytes: [u8; 16] = rng.gen();

    Ok(Vec::from(bytes))
}

custom_error!{ pub UnidentifiedaccessError
    NoProfileKey{uuid: Uuid} = "Cannot generate an unidentified access key for user {uuid}: We do not know their profile key! This would not matter for a user with UnidentifiedAccessMode::UNRESTRICTED.",
    PeerDisallowsSealedSender{uuid: Uuid} = "Tried to generatet an unidentified access key for peer {uuid}, but this user has disabled unidentified access!",
    UnrecognizedUser{address: AuxinAddress} = "Cannot generate an unidentified access key for address {address} as that is not a recognized peer.",
    NoProfile{uuid: Uuid} = "Attempted to generate an unidenttified access key for peer {uuid}, but this user has no profile field whatsoever on record with this Auxin instance. We cannot retrieve their profile key.",
}

fn get_unidentified_access_for_peer<Rng: CryptoRng + RngCore>(peer: &PeerRecord, _context: &AuxinContext<Rng>, rng: &mut Rng) -> Result<Vec<u8>> {
    match &peer.profile {
		Some(p) => match p.unidentified_access_mode {
			UnidentifiedAccessMode::UNRESTRICTED => {
				debug!("User {} has unrestricted unidentified access, generating random key.", peer.uuid);
				Ok(get_unidentified_access_unrestricted(rng)?)
			},
            UnidentifiedAccessMode::ENABLED => {
				debug!("User {} accepts unidentified sender messages, generating an unidentified access key from their profile key.", peer.uuid);
				match &peer.profile_key { 
                    Some(pk) => Ok(get_unidentified_access_for_key(pk)?),
                    None => { return Err( Box::new( UnidentifiedaccessError::NoProfileKey{ uuid: peer.uuid } )); },
                }
			},
            UnidentifiedAccessMode::DISABLED => Err(Box::new(UnidentifiedaccessError::PeerDisallowsSealedSender{ uuid: peer.uuid } )),
		},
		None => Err(Box::new(UnidentifiedaccessError::NoProfile{ uuid: peer.uuid } )),
	}
}

/// Returns Some if the user accepts unidentified sender messages, None if not. Also returns None if this is not a known peer.
pub fn get_unidentified_access_for<Rng: CryptoRng + RngCore>(peer_address: &AuxinAddress, context: &AuxinContext<Rng>, rng: &mut Rng) -> Result<Vec<u8>> {
    match context.peer_cache.get(peer_address) {
        Some(peer) => get_unidentified_access_for_peer(peer, context, rng),
		None => Err(Box::new(UnidentifiedaccessError::UnrecognizedUser{ address: peer_address.clone() } )),
    }
}