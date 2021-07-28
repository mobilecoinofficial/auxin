use address::{AuxinAddress, AuxinDeviceAddress, E164};
use aes_gcm::{Nonce, aead::{Aead, NewAead}, aead::Payload};
use libsignal_protocol::{IdentityKeyPair, InMemIdentityKeyStore, InMemPreKeyStore, InMemSenderKeyStore, InMemSessionStore, InMemSignedPreKeyStore, PublicKey, SenderCertificate};
use log::debug;
use message::MessageOut;
use net::{AuxinNetManager, AuxinHttpsConnection};
use serde_json::json;
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
use state::{AuxinStateManager, PeerRecord, PeerRecordStructure, PeerStore, UnidentifiedAccessMode};

use crate::{discovery::{AttestationResponseList, DirectoryAuthResponse, DiscoveryRequest, DiscoveryResponse, ENCLAVE_ID}, message::AuxinMessageList, net::common_http_headers};

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
    pub address: AuxinDeviceAddress,
    pub password: String,
    pub profile_key: ProfileKey,
    pub identity_keys: IdentityKeyPair,
    pub reg_id: u32,
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
        our_auth_value.push_str(self.address.address.get_phone_number().unwrap());
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

/// Wrapper type to force Rust to recognize libsignal ctx as "Send"
#[derive(Clone, Copy, Default)]
pub struct SignalCtx {
    ctx: libsignal_protocol::Context,
}

impl SignalCtx { 
    pub fn get(&self) -> libsignal_protocol::Context { 
        self.ctx.clone()
    }
}

// Dark magic! may cause crashes! completely unavoidable! Yay!
unsafe impl Send for SignalCtx {}

#[allow(unused)] // TODO: Remove this after we can send/remove a message.
// This is the structure that an AuxinStateHandler builds and saves.
pub struct AuxinContext {
    pub identity: LocalIdentity,
    pub sender_certificate: Option<SenderCertificate>,

    pub peer_cache: PeerRecordStructure,
    pub session_store: InMemSessionStore,
    pub pre_key_store: InMemPreKeyStore,
    pub signed_pre_key_store: InMemSignedPreKeyStore,
    pub identity_store: InMemIdentityKeyStore,
    pub sender_key_store: InMemSenderKeyStore,

    pub config: AuxinConfig,
    pub report_as_online: bool,

    pub ctx: SignalCtx,
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

impl AuxinContext { 
    fn get_unidentified_access_unrestricted<R>(&mut self, rng: &mut R) -> Result<Vec<u8>> where R: RngCore + CryptoRng {
        let bytes: [u8; 16] = rng.gen();
    
        Ok(Vec::from(bytes))
    }

    pub fn get_unidentified_access_for<R>(&mut self, peer_address: &AuxinAddress, rng: &mut R) -> Result<Vec<u8>> where R: RngCore + CryptoRng {
        let peer = self.peer_cache.get(peer_address);
        if peer.is_none() {
            return Err(Box::new(UnidentifiedaccessError::UnrecognizedUser{ address: peer_address.clone() } ))
        }
        let peer = peer.unwrap();

        match &peer.profile {
            Some(p) => match p.unidentified_access_mode {
                UnidentifiedAccessMode::UNRESTRICTED => {
                    debug!("User {} has unrestricted unidentified access, generating random key.", peer.uuid);
                    Ok(self.get_unidentified_access_unrestricted(rng)?)
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
    pub fn get_signal_ctx(&self) -> &SignalCtx { 
        &self.ctx
    }
}

pub struct AuxinApp<R, N, S> where R: RngCore + CryptoRng, N: AuxinNetManager, S: AuxinStateManager {
    net: N, 
    state_manager: S, 
    context: AuxinContext, 
    rng: R,
    http_client: N::C,
}


custom_error!{ pub AuxinInitError
    CannotConnect{msg: String} = "Attempt to connect to Signal via HTTPS failed: {msg}.",
    CannotRequestSenderCert{msg: String} = "Unable to send a \"Sender Certificate\" request: {msg}.",
}

custom_error!{ pub SendMessageError
    CannotMakeMessageRequest{msg: String} = "Unable to send a message-send request: {msg}.",
    CannotSendAuthUpgrade{msg: String} = "Unable request auth upgrade: {msg}.",
    CannotSendAttestReq{msg: String} = "Unable to request attestations: {msg}.",
    CannotSendDiscoveryReq{msg: String} = "Unable to send discovery request to remote secure enclave: {msg}.",
}

custom_error!{ pub StateSaveError
    CannotSaveForPeer{msg: String} = "Couldn't save files for a peer's sessions and profile: {msg}.",
}

impl<R, N, S>  AuxinApp<R, N, S> where R: RngCore + CryptoRng, N: AuxinNetManager, S: AuxinStateManager {
    pub async fn new(local_phone_number: E164, config: AuxinConfig, mut net: N, mut state_manager: S, rng: R) -> Result<Self> {
        let trust_root = sealed_sender_trust_root();

        let local_identity = state_manager.load_local_identity(&local_phone_number)?;

        let sender_cert_request: http::Request<String> = local_identity.build_sendercert_request()?;
        //TODO: Better error handling here.
        let mut http_client = net.connect_to_signal_https().await.map_err(|e| Box::new(AuxinInitError::CannotConnect{msg: format!("{:?}", e)}))?;
        
        //TODO: Better error handling here.
        let sender_cert_response = http_client.request(sender_cert_request).await.map_err(|e| Box::new(AuxinInitError::CannotRequestSenderCert{msg: format!("{:?}", e)}))?;

        assert!(sender_cert_response.status().is_success());

        let cert_structure : serde_json::Value = serde_json::from_str(sender_cert_response.body())?;
        let encoded_cert_str = cert_structure.get("certificate").unwrap();
        let temp_vec = base64::decode(encoded_cert_str.as_str().unwrap())?;
        let sender_cert = libsignal_protocol::SenderCertificate::deserialize(temp_vec.as_slice())?;

        if sender_cert.validate(&trust_root, generate_timestamp() as u64)? { 
            println!("Confirmed our sender certificate is valid!");
        } else {
            panic!("Invalid sender certificate!");
        }

        let mut context = state_manager.load_context(&local_identity, config)?;
        context.sender_certificate = Some(sender_cert);

        Ok(Self {
            net,
            state_manager,
            context,
            rng,
            http_client,
        })
    }

    pub async fn send_message(&mut self, recipient_addr: &AuxinAddress, message: MessageOut) -> Result<()> {
		let recipient_addr = self.context.peer_cache.complete_address(&recipient_addr).or(Some(recipient_addr.clone())).unwrap();
		let recipient = self.context.peer_cache.get(&recipient_addr);

        //If this is an unknown peer, retrieve their UUID and store an entry.
        if recipient.is_none() {
            self.retrieve_and_store_peer_info(recipient_addr.get_phone_number().unwrap()).await?;
        }
		//let recipient = self.context.peer_cache.get(&recipient_addr).unwrap();
        let recipient_addr = self.context.peer_cache.complete_address(&recipient_addr).unwrap();
        let message_list = AuxinMessageList {
            messages: vec![message],
            remote_address: recipient_addr.clone(),
        };

        let outgoing_push_list = message_list.generate_sealed_messages_to_all_devices(&mut self.context, &mut self.rng, generate_timestamp()).await?;

        let request: http::Request<String> = outgoing_push_list.build_http_request(&recipient_addr, &mut self.context, &mut self.rng)?;
        debug!("Attempting to send message: {:?}", request);
        let message_response = self.http_client.request(request).await.map_err(|e| Box::new(SendMessageError::CannotMakeMessageRequest{msg: format!("{:?}", e)}))?;
    
        debug!("Got response to attempt to send message: {:?}", message_response);
        debug!("Response body is: {:?}", message_response.body() );
        self.state_manager.save_peer_record(&recipient_addr, &self.context).map_err(|e| Box::new(StateSaveError::CannotSaveForPeer{msg: format!("{:?}", e)}))?;
        self.state_manager.save_peer_sessions(&recipient_addr, &self.context).map_err(|e| Box::new(StateSaveError::CannotSaveForPeer{msg: format!("{:?}", e)}))?;
    
        Ok(())
    }

    pub async fn retrieve_and_store_peer_info(&mut self, recipient_phone:&E164) -> Result<()>{ 
        let uuid = self.make_discovery_request(recipient_phone).await?;
        let new_id = self.context.peer_cache.last_id + 1; 
        self.context.peer_cache.last_id = new_id;
        // TODO: Retrieve device IDs and such.
        let peer_record = PeerRecord {
            id: new_id,
            number: recipient_phone.clone(),
            uuid,
            profile_key: None,
            profile_key_credential: None,
            contact: None,
            profile: None,
            device_ids_used: Vec::default(),
        };
        self.context.peer_cache.push(peer_record);
        Ok(())
    }

    pub async fn make_discovery_request(&mut self, recipient_phone:&E164) -> Result<Uuid>{ 
        //Get upgraded auth for discovery / directory.
        let auth = self.context.identity.make_auth_header();
        let req = common_http_headers(http::Method::GET, 
            "https://textsecure-service.whispersystems.org/v1/directory/auth",
            auth.as_str())?;
        let req = req.body(String::default())?;

        let auth_upgrade_response = self.http_client.request(req).await
            .map_err(|e| Box::new(SendMessageError::CannotSendAuthUpgrade{msg: format!("{:?}", e)}))?;
        assert!(auth_upgrade_response.status().is_success());

        let upgraded_auth : DirectoryAuthResponse = serde_json::from_str(auth_upgrade_response.body())?;
        let mut upgraded_auth_token = upgraded_auth.username.clone();
        upgraded_auth_token.push_str(":");
        upgraded_auth_token.push_str(&upgraded_auth.password);
        upgraded_auth_token = base64::encode(upgraded_auth_token);
        debug!("Upgraded authorization token: {}", upgraded_auth_token);
        let mut upgraded_auth_header = String::from("Basic ");
        upgraded_auth_header.push_str(&upgraded_auth_token);
        debug!("Upgraded authorization header: {}", upgraded_auth_header);

        //Temporary Keypair for discovery
        let attestation_keys = libsignal_protocol::KeyPair::generate(&mut self.rng);
        let attestation_path = format!("https://api.directory.signal.org/v1/attestation/{}", ENCLAVE_ID);
        let attestation_request= json!({
            "clientPublic": base64::encode(attestation_keys.public_key.public_key_bytes()?),
        });
        let mut req = common_http_headers(http::Method::PUT, 
            &attestation_path,
            upgraded_auth_header.as_str())?;
        let attestation_request = attestation_request.to_string();
        req = req.header("Content-Type", "application/json; charset=utf-8");
        req = req.header("Content-Length", attestation_request.len());
        let req = req.body(attestation_request)?;

        debug!("Sending attestation request: {:?}", req);

        let attestation_response = self.http_client.request(req).await
        .map_err(|e| Box::new(SendMessageError::CannotSendAttestReq{msg: format!("{:?}", e)}))?;

        let attestation_response_body: AttestationResponseList = serde_json::from_str(&attestation_response.body())?;

        attestation_response_body.verify_attestations()?;
        let att_list = attestation_response_body.decode_attestations(&attestation_keys)?;
        
        let receiver_vec = vec![recipient_phone.clone()];
        let query = DiscoveryRequest::new(&receiver_vec, &att_list, &mut self.rng)?;
        let query_str = serde_json::to_string_pretty(&query)?;
        debug!("Built discovery request {}", query_str);


        //we will need these cookies
        let cookies: Vec<&str> = attestation_response.headers().iter().filter_map(| (name, value )| {
            if name.as_str().eq_ignore_ascii_case("Set-Cookie") { 
                value.to_str().ok()
            }
            else {
                None
            }
        }).collect();
        println!("{:?}", cookies);

        let mut filtered_cookies : Vec<String> = Vec::default();
        for cookie in cookies { 
            let spl = cookie.split(";");
            for elem in spl { 
                if elem.contains("ApplicationGatewayAffinityCORS") || elem.contains("ApplicationGatewayAffinity") {
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
        println!("{:?}", resulting_cookie_string);

        let discovery_path = format!("https://api.directory.signal.org/v1/discovery/{}", ENCLAVE_ID);

        let mut req = common_http_headers(http::Method::PUT, 
            &discovery_path,
            upgraded_auth_header.as_str())?;

        req = req.header("Content-Type", "application/json; charset=utf-8");
        req = req.header("Content-Length", query_str.len());
        req = req.header("Cookie", resulting_cookie_string);
        let req = req.body(query_str)?;

        let response = self.http_client.request(req).await
            .map_err(|e| Box::new(SendMessageError::CannotSendDiscoveryReq{msg: format!("{:?}", e)}))?;
        debug!("{:?}", response);

        let discovery_response: DiscoveryResponse = serde_json::from_str(response.body())?;
        let decrypted = discovery_response.decrypt(&att_list)?;
        let uuid = Uuid::from_slice(decrypted.as_slice())?;
        debug!("Successfully decoded discovery response! The recipient's UUID is: {:?}", uuid);
        Ok(uuid)
    }
}

impl<R, N, S> Drop for AuxinApp<R, N, S> where R: RngCore + CryptoRng, N: AuxinNetManager, S: AuxinStateManager {
    fn drop(&mut self) {
        // Make sure all data gets saved first.
        self.state_manager.save_entire_context(&self.context).unwrap();
        self.state_manager.flush(&self.context).unwrap();
    }
}