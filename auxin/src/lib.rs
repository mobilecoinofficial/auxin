#![feature(associated_type_bounds)]

use address::{AuxinAddress, AuxinDeviceAddress, E164};
use aes_gcm::{Nonce, aead::{Aead, NewAead}, aead::Payload};
use auxin_protos::{WebSocketMessage, WebSocketMessage_Type, WebSocketRequestMessage, WebSocketResponseMessage};
use futures::{Sink, SinkExt, Stream, StreamExt};
use libsignal_protocol::{IdentityKey, IdentityKeyPair, IdentityKeyStore, InMemIdentityKeyStore, InMemPreKeyStore, InMemSenderKeyStore, InMemSessionStore, InMemSignedPreKeyStore, ProtocolAddress, PublicKey, SenderCertificate, process_prekey_bundle};
use log::{debug, info, warn};
use message::{MessageIn, MessageInError, MessageOut};
use net::{AuxinHttpsConnection, AuxinNetManager, AuxinWebsocketConnection};
use serde_json::json;
use uuid::Uuid;
use std::{error::Error, pin::Pin, time::{SystemTime, UNIX_EPOCH}};
use custom_error::custom_error;
use std::fmt::Debug;

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
use state::{AuxinStateManager, PeerIdentity, PeerInfoReply, PeerRecord, PeerRecordStructure, PeerStore, UnidentifiedAccessMode};

use crate::{discovery::{AttestationResponseList, DirectoryAuthResponse, DiscoveryRequest, DiscoveryResponse, ENCLAVE_ID}, message::{AuxinMessageList, MessageSendMode}, net::common_http_headers, state::ForeignPeerProfile};

pub const PROFILE_KEY_LEN: usize = 32;

pub type ProfileKey = [u8; PROFILE_KEY_LEN];

#[derive(Clone, Debug, Default)]
pub struct AuxinConfig { }

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

pub fn get_unidentified_access_for_key(profile_key: &String) -> Result<Vec<u8>> {
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
    pub net: N, 
    pub state_manager: S, 
    pub context: AuxinContext, 
    pub rng: R,
    pub(crate) http_client: N::C,
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
        let local_identity = state_manager.load_local_identity(&local_phone_number)?;
        //TODO: Better error handling here.
        let http_client = net.connect_to_signal_https().await.map_err(|e| Box::new(AuxinInitError::CannotConnect{msg: format!("{:?}", e)}))?;

        let context = state_manager.load_context(&local_identity, config)?;

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
            self.retrieve_and_store_peer(recipient_addr.get_phone_number().unwrap()).await?;
        }
		//let recipient = self.context.peer_cache.get(&recipient_addr).unwrap();
        let recipient_addr = self.context.peer_cache.complete_address(&recipient_addr).unwrap();
        let recipient = self.context.peer_cache.get(&recipient_addr).unwrap().clone();
        let device_count = recipient.device_ids_used.len();
        // Corrupt data / missing device list! 
        if (device_count == 0) || recipient.profile.is_none() {
            self.fill_peer_info(&recipient_addr).await?;
        }

        let recipient = self.context.peer_cache.get(&recipient_addr).unwrap().clone();
        
        let message_list = AuxinMessageList {
            messages: vec![message],
            remote_address: recipient_addr.clone(),
        };

        // Can we do sealed sender messages here? 
        let sealed_sender: bool = self.context.peer_cache.get(&recipient_addr).unwrap().supports_sealed_sender();

        let mode = match sealed_sender { 
            true => { 
                // Make sure we have a sender certificate to do this stuff with.
                self.retrieve_sender_cert().await?;
                MessageSendMode::SealedSender
            }
            false => {
                MessageSendMode::Standard
            }
        };

        let outgoing_push_list = message_list.generate_messages_to_all_devices(&mut self.context, mode, &mut self.rng, generate_timestamp()).await?;

        let request: http::Request<String> = outgoing_push_list.build_http_request(&recipient_addr, mode, &mut self.context, &mut self.rng)?;
        debug!("Attempting to send message: {:?}", request);
        let message_response = self.http_client.request(request).await.map_err(|e| Box::new(SendMessageError::CannotMakeMessageRequest{msg: format!("{:?}", e)}))?;
    
        debug!("Got response to attempt to send message: {:?}", message_response);
        debug!("Response body is: {:?}", message_response.body() );


        if recipient.profile_key.is_some() {
            self.retrieve_profile_key_credential(&recipient_addr).await?;
        }
        //Only necessary if fill_peer_info is called, and we do it in there. 
        //self.state_manager.save_peer_record(&recipient_addr, &self.context).map_err(|e| Box::new(StateSaveError::CannotSaveForPeer{msg: format!("{:?}", e)}))?;
        self.state_manager.save_peer_sessions(&recipient_addr, &self.context).map_err(|e| Box::new(StateSaveError::CannotSaveForPeer{msg: format!("{:?}", e)}))?;
    
        Ok(())
    }

    pub async fn retrieve_sender_cert(&mut self) -> Result<()> {
        let trust_root = sealed_sender_trust_root();

        let sender_cert_request: http::Request<String> = self.context.identity.build_sendercert_request()?;
        //TODO: Better error handling here.
        let sender_cert_response = self.http_client.request(sender_cert_request).await.map_err(|e| Box::new(AuxinInitError::CannotRequestSenderCert{msg: format!("{:?}", e)}))?;
        assert!(sender_cert_response.status().is_success());

        let cert_structure : serde_json::Value = serde_json::from_str(sender_cert_response.body())?;
        let encoded_cert_str = cert_structure.get("certificate").unwrap();
        let temp_vec = base64::decode(encoded_cert_str.as_str().unwrap())?;
        let sender_cert = libsignal_protocol::SenderCertificate::deserialize(temp_vec.as_slice())?;

        if sender_cert.validate(&trust_root, generate_timestamp() as u64)? { 
            debug!("Confirmed our sender certificate is valid!");
        } else {
            panic!("Invalid sender certificate!");
        }
        self.context.sender_certificate = Some(sender_cert);

        Ok(())
    }


    /// Retrieves and fills in core information about a peer that is necessary to send a mmessage to them.
    pub async fn fill_peer_info(&mut self, recipient_addr: &AuxinAddress) -> Result<()> { 
        let signal_ctx = self.context.get_signal_ctx().get().clone();

        let uuid = self.context.peer_cache.get(recipient_addr).unwrap().uuid.clone();

        {
            let mut profile_path: String = "https://textsecure-service.whispersystems.org/v1/profile/".to_string();
            profile_path.push_str(uuid.to_string().as_str());
            profile_path.push_str("/");

            let auth = self.context.identity.make_auth_header();
            
            let req = common_http_headers(http::Method::GET, 
                profile_path.as_str(),
                auth.as_str())?;
            let req = req.body(String::default())?;
            
            let res = self.http_client.request(req).await?;
            debug!("Profile response: {:?}", res);
            let recipient = self.context.peer_cache.get_mut(&recipient_addr).unwrap();

            let prof: ForeignPeerProfile = serde_json::from_str(res.body())?;

            recipient.profile = Some(prof.to_local());
        }

        let peer_info = self.request_peer_info(&uuid).await?.clone();
        let decoded_key = base64::decode(&peer_info.identity_key)?;
        let identity_key = IdentityKey::decode(decoded_key.as_slice())?; 
    
        for device in peer_info.devices.iter() { 
            let recipient = self.context.peer_cache.get_mut(&recipient_addr).unwrap(); 
            //Track device IDs used.
            recipient.device_ids_used.push(device.device_id);
            //Note that we are aware of this peer.
            let addr = ProtocolAddress::new(uuid.to_string(), device.device_id);
            self.context.identity_store.save_identity(&addr, &identity_key, signal_ctx).await?;
        }

        {
            //And now for our own, signal-cli-compatible "Identity Store"
            let recipient = self.context.peer_cache.get_mut(&recipient_addr).unwrap(); 
            if recipient.identity.is_none() {
                recipient.identity = Some(PeerIdentity{
                    identity_key: peer_info.identity_key.clone(),
                    trust_level: Some(1),
                    added_timestamp: Some(generate_timestamp()),
                });
            }
        }

        let pre_key_bundles = peer_info.convert_to_pre_key_bundles()?;

        for (device_id, keys) in pre_key_bundles {
			let peer_address = ProtocolAddress::new(uuid.to_string(), device_id);
            // Initiate a session using foreign PreKey.
            process_prekey_bundle(&peer_address, 
                &mut self.context.session_store, 
                &mut self.context.identity_store, 
                &keys, 
                &mut self.rng,
                signal_ctx).await?;
        }

        self.state_manager.save_peer_record(recipient_addr, &self.context)?;
        Ok(())
    }

    pub async fn retrieve_and_store_peer(&mut self, recipient_phone:&E164) -> Result<()>{ 
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
            identity: None,
        };

        self.context.peer_cache.push(peer_record);

        let address = AuxinAddress::Uuid(uuid);

        self.fill_peer_info(&address).await?;

        Ok(())
    }

    pub async fn request_peer_info(&self, uuid: &Uuid) -> Result<PeerInfoReply> { 

        let mut path: String = "https://textsecure-service.whispersystems.org/v2/keys/".to_string();
        path.push_str(uuid.to_string().as_str());
        path.push_str("/*");

        let auth = self.context.identity.make_auth_header();
        
        let req = common_http_headers(http::Method::GET, 
            path.as_str(),
            auth.as_str())?;
        let req = req.body(String::default())?;
        
        let res = self.http_client.request(req).await?;
        debug!("Peer keys response: {:?}", res);
        let info: PeerInfoReply = serde_json::from_str(res.body().as_str())?;
        Ok(info)
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

    pub async fn retrieve_profile_key_credential(&mut self, recipient: &AuxinAddress) -> Result<()> {

        debug!("a");
        if let Some(peer) = self.context.peer_cache.get(recipient) {
            if let Some(profile_key) = &peer.profile_key {

                let mut profile_key_bytes: [u8; PROFILE_KEY_LEN] = [0;PROFILE_KEY_LEN];
                let temp_bytes = base64::decode(profile_key)?;
                profile_key_bytes.copy_from_slice(&(temp_bytes)[0..PROFILE_KEY_LEN]);
                let uuid = recipient.get_uuid()?;
                let randomness: [u8;32] = self.rng.gen();
                let server_secret_params = zkgroup::api::ServerSecretParams::generate(randomness);
                let server_public_params = server_secret_params.get_public_params();        
                let randomness: [u8;32] = self.rng.gen();
                let request_context = server_public_params.create_profile_key_credential_request_context(randomness, *uuid.as_bytes(), zkgroup::api::profiles::ProfileKey::create(profile_key_bytes));    
                let request = request_context.get_request();
                let encoded_request = hex::encode(&bincode::serialize(&request).unwrap());

                let get_path = format!("https://textsecure-service.whispersystems.org/v1/profile/{}/{}/{}", uuid.to_string(), 1, encoded_request);

                let unidentified_access = self.context.get_unidentified_access_for(recipient, &mut self.rng)?;
                let unidentified_access = base64::encode(unidentified_access);
                let req = http::Request::builder()
                    .uri(get_path)
                    .method(http::Method::GET)
                    .header("Unidentified-Access-Key", unidentified_access)
                    .body(String::default())?;
                debug!("Requesitng profile key credential with {:?}", req);
                let response = self.http_client.request(req).await?;

                debug!("{:?}", response);
            }
        }
        return Ok(());
    }
}

impl<R, N, S> Drop for AuxinApp<R, N, S> where R: RngCore + CryptoRng, N: AuxinNetManager, S: AuxinStateManager {
    fn drop(&mut self) {
        // Make sure all data gets saved first.
        self.state_manager.save_entire_context(&self.context).unwrap();
        self.state_manager.flush(&self.context).unwrap();
    }
}


#[derive(Debug)]
pub enum ReceiveError { 
    NetSpecific(String),
    SendErr(String),
    InError(MessageInError),
    StoreStateError(String),
    ReconnectErr(String),
    UnknownWebsocketTy,
}
impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self { 
            Self::NetSpecific(e) => write!(f, "Net manager implementation produced an error: {:?}", e),
            Self::SendErr(e) => write!(f, "Net manager errored while attempting to send a response: {:?}", e),
            Self::InError(e) => write!(f, "Unable to decode or decrypt message: {:?}", e),
            Self::StoreStateError(e) => write!(f, "Unable to store state after receiving message: {:?}", e),
            Self::ReconnectErr(e) => write!(f, "Error while attempting to reconnect websocket: {:?}", e),
            Self::UnknownWebsocketTy => write!(f, "Websocket message type is Unknown!"),
        }
    }
}

impl std::error::Error for ReceiveError {}

impl From<MessageInError> for ReceiveError {
    fn from(val: MessageInError) -> Self {
        Self::InError(val)
    }
}

type OutstreamT<N> =Pin<Box<dyn Sink<<<N as AuxinNetManager>::W as AuxinWebsocketConnection>::Message, Error=<<N as AuxinNetManager>::W as AuxinWebsocketConnection>::SinkError>>>;
type InstreamT<N> =Pin<Box<dyn Stream<Item = std::result::Result<<<N as AuxinNetManager>::W as AuxinWebsocketConnection>::Message, <<N as AuxinNetManager>::W as AuxinWebsocketConnection>::StreamError>>>>;

pub struct AuxinReceiver<'a, R, N, S> where R: RngCore + CryptoRng, N: AuxinNetManager, S: AuxinStateManager {
    pub(crate) app: &'a mut AuxinApp<R, N, S>,
    //Disregard these type signatures. They are weird and gnarly for unavoidable reasons. 
    pub(crate) outstream: OutstreamT<N>, 
    pub(crate) instream: InstreamT<N>,
}

impl<'a, R, N, S> AuxinReceiver<'a, R, N, S> where  R: RngCore + CryptoRng, N: AuxinNetManager, S: AuxinStateManager {

    pub async fn new(app: &'a mut AuxinApp<R,N,S>) -> Result<AuxinReceiver<'a, R, N, S>> {
        let ws = app.net.connect_to_signal_websocket(&app.context.identity).await?;
        let (outstream, instream) = ws.into_streams();
        Ok(AuxinReceiver { 
            app,
            outstream,
            instream,
        })
    }

    /// Notify the server that we have received a message. If it is a non-receipt Signal message, we will send our receipt indicating we got this message.
    async fn acknowledge_message(&mut self, msg: &Option<MessageIn>, req: &WebSocketRequestMessage) -> std::result::Result<(), ReceiveError> {
        // Sending responses goes here. 
        let reply_id = req.get_id();
        let mut res = WebSocketResponseMessage::default();
        res.set_id(reply_id);
        res.set_status(200); // Success
        res.set_message(String::from("OK"));
        res.set_headers(req.get_headers().clone().into());
        let mut res_m = WebSocketMessage::default();
        res_m.set_response(res);
        res_m.set_field_type(WebSocketMessage_Type::RESPONSE);
        
        self.outstream.send(res_m.into()).await
        .map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;

        if let Some(msg) = msg {
            // Send receipts if we have to.
            if msg.needs_receipt() { 
                let receipt = msg.generate_receipt(auxin_protos::ReceiptMessage_Type::DELIVERY);
                self.app.send_message(&msg.remote_address.address, receipt).await
                    .map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;
            }
        }

        self.outstream.flush().await
            .map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;
        Ok(())
    }
    async fn next_inner(&mut self, wsmessage: &auxin_protos::WebSocketMessage) -> std::result::Result<Option<MessageIn>, ReceiveError> {

        match wsmessage.get_field_type() {
            auxin_protos::WebSocketMessage_Type::UNKNOWN => Err(ReceiveError::UnknownWebsocketTy),
            auxin_protos::WebSocketMessage_Type::REQUEST => {
                let req = wsmessage.get_request();

                // Done this way to ensure invalid messages are still acknowledged, to clear them from the queue.
                let msg = match MessageIn::decode_envelope_bin(req.get_body(), &mut self.app.context, &mut self.app.rng).await {
                    Err(MessageInError::ProtocolError(e)) => {
                        warn!("Message failed to decrypt - ignoring error and continuing to receive messages to clear out prior bad state. Error was: {:?}", e);
                        None
                    },
                    Err(MessageInError::DecodingProblem(e)) => {
                        warn!("Message failed to decode (bad envelope?) - ignoring error and continuing to receive messages to clear out prior bad state. Error was: {:?}", e);
                        None
                    },
                    Err(e) => { return Err(e.into());},
                    Ok(m) => Some(m),
                };
                //This will at least acknowledge to WebSocket that we have received this message.
                self.acknowledge_message(&msg, &req).await?;

                if let Some(msg) = &msg {
                    self.app.state_manager.save_peer_sessions(&msg.remote_address.address, &self.app.context)
                        .map_err(|e| ReceiveError::StoreStateError(format!("{:?}", e)))?;
                }
                Ok(msg)
            },
            auxin_protos::WebSocketMessage_Type::RESPONSE => {
                let res = wsmessage.get_response();
                info!("WebSocket response message received: {:?}", res);
                Ok(None)
            },
        }
    }
    /// Polls for the next available message.  Returns none for end of stream. 
    pub async fn next(&mut self) -> Option<std::result::Result<MessageIn, ReceiveError>> {
        //Try up to 64 times if necessary.
        for _ in 0..64 {
            let msg = self.instream.next().await;
            
            match msg {
                None => {return None;},
                Some(Err(e)) => {return Some(Err(ReceiveError::NetSpecific(format!("{:?}",e))));},
                Some(Ok(m)) => {
                    let wsmessage: WebSocketMessage = m.into();
                    //Check to see if we're done.
                    if wsmessage.get_field_type() == WebSocketMessage_Type::REQUEST  { 
                        let req = wsmessage.get_request();
                        if req.has_path() { 
                            // The server has sent us all the messages it has waiting for us.
                            if req.get_path().contains("/api/v1/queue/empty") {
                                debug!("Received an /api/v1/queue/empty message. Message receiving complete.");
                                //Acknowledge we received the end-of-queue and do many clunky error-handling things:
                                let res = self.acknowledge_message(&None, &req).await
                                    .map_err(|e| ReceiveError::SendErr(format!("{:?}", e)));
                                let res = match res {
                                    Ok(()) => None,
                                    Err(e) => Some(Err(e)),
                                };
                                
                                // Receive operation is done. Indicate there are no further messages left to poll for.
                                return res; //Usually this returns None.
                            }
                        }
                    }

                    //Actually parse our message otherwise.
                    match self.next_inner(&wsmessage).await {
                        Ok(Some(message)) => {return Some(Ok(message))},
                        Ok(None) => /*Message failed to decode - ignoring error and continuing to receive messages to clear out prior bad state*/ {},
                        Err(e) => {return Some(Err(e))},
                    }

                },
            }
        }
        None 
    }

    /// Convenience method so we don't have to work around the borrow checker to call send_message on our app when the Receiver has an &mut app.
    pub async fn send_message(&mut self, recipient_addr: &AuxinAddress, message: MessageOut) -> Result<()> {
        self.app.send_message(recipient_addr, message).await
    }

    /// Request additional messages (to continue polling for messages after "/api/v1/queue/empty" has been sent). This is a GET request with path GET /v1/messages/
    pub async fn refresh(&mut self) -> std::result::Result<(), ReceiveError> { 
        let mut req = WebSocketRequestMessage::default();
        req.set_id(self.app.rng.next_u64());
        req.set_verb("GET".to_string()); 
        req.set_path("/v1/messages/".to_string());
        let mut req_m = WebSocketMessage::default();
        req_m.set_request(req);
        req_m.set_field_type(WebSocketMessage_Type::REQUEST);
        
        self.outstream.send(req_m.into()).await
            .map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;

        self.outstream.flush().await
            .map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;

        Ok(())
    }

    pub async fn reconnect(&mut self) -> Result<()> {         

        self.outstream.close().await.map_err(|e| ReceiveError::ReconnectErr(format!("Could not close: {:?}", e)))?;
        let ws = self.app.net.connect_to_signal_websocket(&self.app.context.identity).await?;
        let (outstream, instream) = ws.into_streams();

        self.outstream = outstream; 
        self.instream = instream;
        
        Ok(())
    }
}