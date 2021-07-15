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
pub mod discovery;

/// Self-signing root cert for TLS connections to Signal's web API..
pub const SIGNAL_TLS_CERT : &str = include_str!("../data/whisper.pem");
/// Trust anchor for IAS - required to validate certificate chains for remote SGX attestation.
pub const IAS_TRUST_ANCHOR : &[u8] = include_bytes!("../data/ias.der");


use rand::{CryptoRng, Rng, RngCore};
//use serde::{Serialize, Deserialize};
use state::{PeerRecordStructure, PeerStore, UnidentifiedAccessMode};

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

impl LocalIdentity {
    /// Required HTTP header for our Signal requests.
    /// Authorization: "Basic {AUTH}""
    /// AUTH is a base64-encoding of: NUMBER:B64PWD, where NUMBER is our phone number and 
    /// B64PWD is our base64-encoded password.
    /// NOTE: Discovery requests will require a different user-ID and password, which is retrieved with a GET request to https://textsecure-service.whispersystems.org/v1/directory/auth
    pub fn make_auth_header(&self) -> String {
        let mut our_auth_value = String::default();
        // We have to supply our own address as a phone number
        // It will not accept this if we use our UUID. 
        our_auth_value.push_str(self.our_address.address.get_phone_number().unwrap());
        our_auth_value.push_str(":");
        our_auth_value.push_str(&self.password);


        let b64_auth = base64::encode(our_auth_value);

        let mut our_auth = String::from("Basic ");
        our_auth.push_str(b64_auth.as_str());

        our_auth
    }

    /// Build a request for a "Sender Certificate," which is required in order to deliver "sealed sender" messages.
    pub fn build_sendercert_request<Body: Default>(&self) -> Result<http::Request<Body>> {
        let req = crate::net::common_http_headers(http::Method::GET, 
                            "https://textsecure-service.whispersystems.org/v1/certificate/delivery", 
                            self.make_auth_header().as_str() )?;
        Ok(req.body(Body::default())?)
    }
}

#[allow(unused)] // TODO: Remove this after we can send/remove a message.
// This is the structure that an AuxinStateHandler builds and saves.
pub struct AuxinContext<R> where R: RngCore + CryptoRng {
    pub our_identity: LocalIdentity,
    pub our_sender_certificate: SenderCertificate,

    pub peer_cache: PeerRecordStructure,
    pub session_store: InMemSessionStore,
    pub pre_key_store: InMemPreKeyStore,
    pub signed_pre_key_store: InMemSignedPreKeyStore,
    pub identity_store: InMemIdentityKeyStore,
    pub sender_key_store: InMemSenderKeyStore,
    pub rng: R,

    pub config: AuxinConfig,
    pub signal_ctx: libsignal_protocol::Context,
    pub report_as_online: bool,
}

fn get_unidentified_access_for_key(profile_key: &String) -> Result<Vec<u8>> {
    let profile_key_bytes = base64::decode(profile_key)?;
    let profile_key = aes_gcm::Key::from_slice(profile_key_bytes.as_slice());
    let cipher = aes_gcm::Aes256Gcm::new(profile_key);
    //Libsignal-service-java enciphers 16 zeroes with a (re-used) nonce of 12 zeroes
    //to get this access key, unless I am horribly misreading it. 
    let zeroes: [u8; 16] = [0; 16];
    let nonce: [u8; 12] = [0; 12];
    let nonce = Nonce::from_slice(&nonce);

    let payload = Payload{msg: &zeroes, aad: b"" };

    Ok(cipher.encrypt(&nonce, payload)?)
}

custom_error!{ pub UnidentifiedaccessError
    NoProfileKey{uuid: Uuid} = "Cannot generate an unidentified access key for user {uuid}: We do not know their profile key! This would not matter for a user with UnidentifiedAccessMode::UNRESTRICTED.",
    PeerDisallowsSealedSender{uuid: Uuid} = "Tried to generatet an unidentified access key for peer {uuid}, but this user has disabled unidentified access!",
    UnrecognizedUser{address: AuxinAddress} = "Cannot generate an unidentified access key for address {address} as that is not a recognized peer.",
    NoProfile{uuid: Uuid} = "Attempted to generate an unidenttified access key for peer {uuid}, but this user has no profile field whatsoever on record with this Auxin instance. We cannot retrieve their profile key.",
}

impl<R> AuxinContext<R> where R: RngCore + CryptoRng { 
    fn get_unidentified_access_unrestricted(&mut self) -> Result<Vec<u8>> {
        let bytes: [u8; 16] = self.rng.gen();
    
        Ok(Vec::from(bytes))
    }

    pub fn get_unidentified_access_for(&mut self, peer_address: &AuxinAddress) -> Result<Vec<u8>> {
        let peer = self.peer_cache.get(peer_address);
        if peer.is_none() {
            return Err(Box::new(UnidentifiedaccessError::UnrecognizedUser{ address: peer_address.clone() } ))
        }
        let peer = peer.unwrap();

        match &peer.profile {
            Some(p) => match p.unidentified_access_mode {
                UnidentifiedAccessMode::UNRESTRICTED => {
                    debug!("User {} has unrestricted unidentified access, generating random key.", peer.uuid);
                    Ok(self.get_unidentified_access_unrestricted()?)
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
}