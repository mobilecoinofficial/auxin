#![feature(associated_type_bounds)]
#![deny(bare_trait_objects)]

use address::{AddressError, AuxinAddress, AuxinDeviceAddress, E164};
use aes_gcm::{
	aead::Payload,
	aead::{Aead, NewAead},
	Aes256Gcm, Nonce,
};
use attachment::{download::{self, AttachmentDownloadError}, upload::{AttachmentUploadError, PreUploadToken}};
use auxin_protos::AttachmentPointer;
use custom_error::custom_error;
use futures::{TryFutureExt};
use libsignal_protocol::{
	process_prekey_bundle, IdentityKey, IdentityKeyPair, IdentityKeyStore, InMemIdentityKeyStore,
	InMemPreKeyStore, InMemSenderKeyStore, InMemSessionStore, InMemSignedPreKeyStore,
	ProtocolAddress, PublicKey, SenderCertificate,
};
use log::{debug, error};
use message::MessageOut;
use net::{api_paths::SIGNAL_CDN, AuxinHttpsConnection, AuxinNetManager};
use serde_json::json;
use std::{fmt::Debug};
use std::{
	error::Error,
	time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub mod address;
pub mod attachment;
pub mod discovery;
pub mod message;
pub mod net;
pub mod receiver;
pub mod state;

/// Self-signing root cert for TLS connections to Signal's web API..
pub const SIGNAL_TLS_CERT: &str = include_str!("../data/whisper.pem");
/// Trust anchor for IAS - required to validate certificate chains for remote SGX attestation.
pub const IAS_TRUST_ANCHOR: &[u8] = include_bytes!("../data/ias.der");

use rand::{CryptoRng, Rng, RngCore};
use state::{
	AuxinStateManager, PeerIdentity, PeerInfoReply, PeerRecord, PeerRecordStructure, PeerStore,
	UnidentifiedAccessMode,
};

use crate::{
	attachment::download::EncryptedAttachment, 
	discovery::{
		AttestationResponseList, DirectoryAuthResponse, DiscoveryRequest, DiscoveryResponse,
		ENCLAVE_ID,
	}, 
	message::{
		fix_protobuf_buf, 
		AuxinMessageList, 
		MessageSendMode}, 
	net::common_http_headers, 
	state::{
		ForeignPeerProfile,
		ProfileResponse
	}
};

pub const PROFILE_KEY_LEN: usize = 32;

pub type ProfileKey = [u8; PROFILE_KEY_LEN];

#[derive(Clone, Debug, Default)]
pub struct AuxinConfig {}

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn generate_timestamp() -> u64 {
	let now = SystemTime::now();
	now.duration_since(UNIX_EPOCH)
		.expect("Time went backwards")
		.as_millis() as u64
}

/// Retrieves trust root for all "Sealed Sender" messages.
pub fn sealed_sender_trust_root() -> PublicKey {
	PublicKey::deserialize(
		base64::decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF")
			.unwrap()
			.as_slice(),
	)
	.unwrap()
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
	/// AUTH is a base64-encoding of: NUMBER:B64PWD, where NUMBER is our UUID and
	/// B64PWD is our base64-encoded password. It used to require NUMBER=E164 phone number but this has been changed.
	/// NOTE: Discovery requests will require a different user-ID and password, which is retrieved with a GET request to https://textsecure-service.whispersystems.org/v1/directory/auth
	pub fn make_auth_header(&self) -> String {
		let mut our_auth_value = String::default();
		our_auth_value.push_str(&self.address.address.get_uuid().unwrap().to_string());
		our_auth_value.push_str(":");
		our_auth_value.push_str(&self.password);

		let b64_auth = base64::encode(our_auth_value);

		let mut our_auth = String::from("Basic ");
		our_auth.push_str(b64_auth.as_str());

		our_auth
	}

	/// Build a request for a "Sender Certificate," which is required in order to deliver "sealed sender" messages.
	pub fn build_sendercert_request<Body: Default>(&self) -> Result<http::Request<Body>> {
		let req = crate::net::common_http_headers(
			http::Method::GET,
			"https://textsecure-service.whispersystems.org/v1/certificate/delivery",
			self.make_auth_header().as_str(),
		)?;
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

	let payload = Payload {
		msg: &zeroes,
		aad: b"",
	};

	Ok(cipher.encrypt(&nonce, payload)?)
}

custom_error! { pub UnidentifiedAccessError
	NoProfileKey{uuid: Uuid} = "Cannot generate an unidentified access key for user {uuid}: We do not know their profile key! This would not matter for a user with UnidentifiedAccessMode::UNRESTRICTED.",
	PeerDisallowsSealedSender{uuid: Uuid} = "Tried to generatet an unidentified access key for peer {uuid}, but this user has disabled unidentified access!",
	UnrecognizedUser{address: AuxinAddress} = "Cannot generate an unidentified access key for address {address} as that is not a recognized peer.",
	NoProfile{uuid: Uuid} = "Attempted to generate an unidenttified access key for peer {uuid}, but this user has no profile field whatsoever on record with this Auxin instance. We cannot retrieve their profile key.",
}

impl AuxinContext {
	fn get_unidentified_access_unrestricted<R>(&mut self, rng: &mut R) -> Result<Vec<u8>>
	where
		R: RngCore + CryptoRng,
	{
		let bytes: [u8; 16] = rng.gen();

		Ok(Vec::from(bytes))
	}

	pub fn get_unidentified_access_for<R>(
		&mut self,
		peer_address: &AuxinAddress,
		rng: &mut R,
	) -> Result<Vec<u8>>
	where
		R: RngCore + CryptoRng,
	{
		let peer = self.peer_cache.get(peer_address);
		if peer.is_none() {
			return Err(Box::new(UnidentifiedAccessError::UnrecognizedUser {
				address: peer_address.clone(),
			}));
		}
		let peer = peer.unwrap();

		let uuid = peer.uuid.unwrap();

		match &peer.profile {
			Some(p) => match p.unidentified_access_mode {
				UnidentifiedAccessMode::UNRESTRICTED => {
					debug!(
						"User {} has unrestricted unidentified access, generating random key.",
						uuid.to_string()
					);
					Ok(self.get_unidentified_access_unrestricted(rng)?)
				}
				UnidentifiedAccessMode::ENABLED => {
					debug!("User {} accepts unidentified sender messages, generating an unidentified access key from their profile key.", uuid.to_string());
					match &peer.profile_key {
						Some(pk) => Ok(get_unidentified_access_for_key(pk)?),
						None => {
							return Err(Box::new(UnidentifiedAccessError::NoProfileKey { uuid }));
						}
					}
				}
				UnidentifiedAccessMode::DISABLED => Err(Box::new(
					UnidentifiedAccessError::PeerDisallowsSealedSender { uuid },
				)),
			},
			None => Err(Box::new(UnidentifiedAccessError::NoProfile { uuid })),
		}
	}
	pub fn get_signal_ctx(&self) -> &SignalCtx {
		&self.ctx
	}
}

pub struct AuxinApp<R, N, S>
where
	R: RngCore + CryptoRng,
	N: AuxinNetManager,
	S: AuxinStateManager,
{
	pub net: N,
	pub state_manager: S,
	pub context: AuxinContext,
	pub rng: R,
	pub(crate) http_client: N::C,
}

custom_error! { pub AuxinInitError
	CannotConnect{msg: String} = "Attempt to connect to Signal via HTTPS failed: {msg}.",
	CannotRequestSenderCert{msg: String} = "Unable to send a \"Sender Certificate\" request: {msg}.",
}

custom_error! { pub SendMessageError
	CannotMakeMessageRequest{msg: String} = "Unable to send a message-send request: {msg}.",
	CannotSendAuthUpgrade{msg: String} = "Unable request auth upgrade: {msg}.",
	CannotSendAttestReq{msg: String} = "Unable to request attestations: {msg}.",
	CannotSendDiscoveryReq{msg: String} = "Unable to send discovery request to remote secure enclave: {msg}.",
}

custom_error! { pub StateSaveError
	CannotSaveForPeer{msg: String} = "Couldn't save files for a peer's sessions and profile: {msg}.",
}

custom_error! { pub PaymentAddressRetrievalError
	NoProfileKey{peer: AuxinAddress} = "Couldn't retrieve payment address for peer {peer} because we do not have a profile key on file for this user.",
	NoPeer{peer: AuxinAddress} = "Cannot retrieve payment address for peer {peer} because we have no record on this user!",
	NoPaymentAddressForUser{peer: AuxinAddress} = "Got profile information for {peer}, but no payment address was included.",
	EncodingError{peer: AuxinAddress, msg: String} = "Error encoding profile/payment-address request for {peer}: {msg}",
	DecodingError{peer: AuxinAddress, msg: String} = "Error decoding profile/payment-address response for {peer}: {msg}",
	DecryptingError{peer: AuxinAddress, msg: String} = "Error decrypting profile/payment-address response for {peer}: {msg}",
	UnidentifiedAccess{peer: AuxinAddress, msg: String} = "Error getting unidentified access for {peer}: {msg}",
	NoUuid{peer: AuxinAddress, err: AddressError} = "No Uuid for {peer}: {err}",
	ErrPeer{peer: AuxinAddress, err: String} = "Error loading peer {peer}: {err}",
}

impl<R, N, S> AuxinApp<R, N, S>
where
	R: RngCore + CryptoRng,
	N: AuxinNetManager,
	S: AuxinStateManager,
{
	pub async fn new(
		local_phone_number: E164,
		config: AuxinConfig,
		mut net: N,
		mut state_manager: S,
		rng: R,
	) -> Result<Self> {
		let local_identity = state_manager.load_local_identity(&local_phone_number)?;
		//TODO: Better error handling here.
		let http_client = net.connect_to_signal_https().map_err(|e| {
			Box::new(AuxinInitError::CannotConnect {
				msg: format!("{:?}", e),
			})
		}).await?;

		let context = state_manager.load_context(&local_identity, config)?;

		Ok(Self {
			net,
			state_manager,
			context,
			rng,
			http_client,
		})
	}

	/// Checks to see if a recipient's information is loaded and takes all actions necessary to fill out a PeerRecord if not.
	pub async fn ensure_peer_loaded(&mut self, recipient_addr: &AuxinAddress) -> Result<()> {
		let recipient_addr = self
			.context
			.peer_cache
			.complete_address(&recipient_addr)
			.or(Some(recipient_addr.clone()))
			.unwrap();
		let recipient = self.context.peer_cache.get(&recipient_addr);

		//If this is an unknown peer, OR if we have their phone number but not their UUID, retrieve their UUID and store an entry.
		if recipient.is_none() || recipient.unwrap().uuid.is_none() {
			self.retrieve_and_store_peer(recipient_addr.get_phone_number().unwrap())
				.await?;
		}
		//let recipient = self.context.peer_cache.get(&recipient_addr).unwrap();
		let recipient_addr = self
			.context
			.peer_cache
			.complete_address(&recipient_addr)
			.unwrap();
		let recipient = self
			.context
			.peer_cache
			.get(&recipient_addr)
			.unwrap()
			.clone();
		let device_count = recipient.device_ids_used.len();
		// Corrupt data / missing device list!
		if (device_count == 0) || recipient.profile.is_none() {
			self.fill_peer_info(&recipient_addr).await?;
		}
		Ok(())
	}

	pub async fn send_message(
		&mut self,
		recipient_addr: &AuxinAddress,
		message: MessageOut,
	) -> Result<()> {
		let recipient_addr = self
			.context
			.peer_cache
			.complete_address(&recipient_addr)
			.or(Some(recipient_addr.clone()))
			.unwrap();

		//Make sure we know everything about this user that we need to.
		self.ensure_peer_loaded(&recipient_addr).await?;

		let recipient_addr = self
			.context
			.peer_cache
			.complete_address(&recipient_addr)
			.or(Some(recipient_addr.clone()))
			.unwrap();

		let message_list = AuxinMessageList {
			messages: vec![message],
			remote_address: recipient_addr.clone(),
		};

		// Can we do sealed sender messages here?
		let sealed_sender: bool = self
			.context
			.peer_cache
			.get(&recipient_addr)
			.unwrap()
			.supports_sealed_sender();

		let mode = match sealed_sender {
			true => {
				// Make sure we have a sender certificate to do this stuff with.
				self.retrieve_sender_cert().await?;
				MessageSendMode::SealedSender
			}
			false => MessageSendMode::Standard,
		};

		let outgoing_push_list = message_list
			.generate_messages_to_all_devices(
				&mut self.context,
				mode,
				&mut self.rng,
				generate_timestamp(),
			)
			.await?;

		let request: http::Request<Vec<u8>> = outgoing_push_list.build_http_request(
			&recipient_addr,
			mode,
			&mut self.context,
			&mut self.rng,
		)?;
		let message_response = self.http_client.request(request).map_err(|e| {
			Box::new(SendMessageError::CannotMakeMessageRequest {
				msg: format!("{:?}", e),
			})
		}).await?;

		debug!(
			"Got response to attempt to send message: {:?}",
			message_response
		);

		//Only necessary if fill_peer_info is called, and we do it in there.
		//self.state_manager.save_peer_record(&recipient_addr, &self.context).map_err(|e| Box::new(StateSaveError::CannotSaveForPeer{msg: format!("{:?}", e)}))?;
		self.state_manager
			.save_peer_sessions(&recipient_addr, &self.context)
			.map_err(|e| {
				Box::new(StateSaveError::CannotSaveForPeer {
					msg: format!("{:?}", e),
				})
			})?;

		Ok(())
	}

	pub async fn retrieve_sender_cert(&mut self) -> Result<()> {
		let trust_root = sealed_sender_trust_root();

		let sender_cert_request: http::Request<Vec<u8>> =
			self.context.identity.build_sendercert_request()?;
		let req_str: String = format!("{:?}", &sender_cert_request);
		//TODO: Better error handling here.
		let sender_cert_response = self
			.http_client
			.request(sender_cert_request)
			.map_err(|e| {
				Box::new(AuxinInitError::CannotRequestSenderCert {
					msg: format!("{:?}", e),
				})
			}).await?;
		if !sender_cert_response.status().is_success() {
			error!(
				"Response to sender certificate request was: {:?}",
				sender_cert_response
			);
			error!("Our request was: {}", req_str);
		}
		assert!(sender_cert_response.status().is_success());

        let sender_cert_response_str = String::from_utf8(sender_cert_response.body().to_vec())?;

		let cert_structure: serde_json::Value = serde_json::from_str(&sender_cert_response_str)?;
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

		// Once you get here, retrieve_and_store_peer() shuld have already been called, so we should definitely have a UUID.
		let uuid = self
			.context
			.peer_cache
			.get(recipient_addr)
			.unwrap()
			.uuid
			.unwrap()
			.clone();

		{
			let mut profile_path: String =
				"https://textsecure-service.whispersystems.org/v1/profile/".to_string();
			profile_path.push_str(uuid.to_string().as_str());
			profile_path.push_str("/");

			let auth = self.context.identity.make_auth_header();

			let req = common_http_headers(http::Method::GET, profile_path.as_str(), auth.as_str())?;
			let req = req.body(Vec::default())?;

			let res = self.http_client.request(req).await?;
			debug!("Profile response: {:?}", res);
			let recipient = self.context.peer_cache.get_mut(&recipient_addr).unwrap();

            let res_str = String::from_utf8(res.body().to_vec())?;

			let prof: ForeignPeerProfile = serde_json::from_str(&res_str)?;

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
			self.context
				.identity_store
				.save_identity(&addr, &identity_key, signal_ctx)
				.await?;
		}

		{
			//And now for our own, signal-cli-compatible "Identity Store"
			let recipient = self.context.peer_cache.get_mut(&recipient_addr).unwrap();
			if recipient.identity.is_none() {
				recipient.identity = Some(PeerIdentity {
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
			process_prekey_bundle(
				&peer_address,
				&mut self.context.session_store,
				&mut self.context.identity_store,
				&keys,
				&mut self.rng,
				signal_ctx,
			)
			.await?;
		}

		self.state_manager
			.save_peer_record(recipient_addr, &self.context)?;
		Ok(())
	}

	pub async fn retrieve_and_store_peer(&mut self, recipient_phone: &E164) -> Result<()> {
		let uuid = self.make_discovery_request(recipient_phone).await?;

		let new_id = self.context.peer_cache.last_id + 1;
		self.context.peer_cache.last_id = new_id;
		// TODO: Retrieve device IDs and such.
		let peer_record = PeerRecord {
			id: new_id,
			number: recipient_phone.clone(),
			uuid: Some(uuid),
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

		let req = common_http_headers(http::Method::GET, path.as_str(), auth.as_str())?;
		let req = req.body(Vec::default())?;

		let res = self.http_client.request(req).await?;
        let res_str = String::from_utf8(res.body().to_vec())?;
		debug!("Peer keys response: {:?}", res);
		let info: PeerInfoReply = serde_json::from_str(&res_str)?;
		Ok(info)
	}

	pub async fn make_discovery_request(&mut self, recipient_phone: &E164) -> Result<Uuid> {
		//Get upgraded auth for discovery / directory.
		let auth = self.context.identity.make_auth_header();
		let req = common_http_headers(
			http::Method::GET,
			"https://textsecure-service.whispersystems.org/v1/directory/auth",
			auth.as_str(),
		)?;
		let req = req.body(Vec::default())?;

		let auth_upgrade_response = self.http_client.request(req).await.map_err(|e| {
			Box::new(SendMessageError::CannotSendAuthUpgrade {
				msg: format!("{:?}", e),
			})
		})?;
		assert!(auth_upgrade_response.status().is_success());

        let auth_upgrade_response_str = String::from_utf8(auth_upgrade_response.body().to_vec())?;

		let upgraded_auth: DirectoryAuthResponse = serde_json::from_str(&auth_upgrade_response_str)?;
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
		let attestation_path = format!(
			"https://api.directory.signal.org/v1/attestation/{}",
			ENCLAVE_ID
		);
		let attestation_request = json!({
			"clientPublic": base64::encode(attestation_keys.public_key.public_key_bytes()?),
		});
		let mut req = common_http_headers(
			http::Method::PUT,
			&attestation_path,
			upgraded_auth_header.as_str(),
		)?;
		let attestation_request = attestation_request.to_string();
		req = req.header("Content-Type", "application/json; charset=utf-8");
		req = req.header("Content-Length", attestation_request.len());
		let req = req.body(attestation_request.into_bytes())?;

		debug!("Sending attestation request: {:?}", req);

		let attestation_response = self.http_client.request(req).await.map_err(|e| {
			Box::new(SendMessageError::CannotSendAttestReq {
				msg: format!("{:?}", e),
			})
		})?;

        let attestation_response_str = String::from_utf8(attestation_response.body().to_vec())?;
		let attestation_response_body: AttestationResponseList = serde_json::from_str(&attestation_response_str)?;

		attestation_response_body.verify_attestations()?;
		let att_list = attestation_response_body.decode_attestations(&attestation_keys)?;

		let receiver_vec = vec![recipient_phone.clone()];
		let query = DiscoveryRequest::new(&receiver_vec, &att_list, &mut self.rng)?;
		let query_str = serde_json::to_string_pretty(&query)?;
		debug!("Built discovery request {}", query_str);

		//we will need these cookies
		let cookies: Vec<&str> = attestation_response
			.headers()
			.iter()
			.filter_map(|(name, value)| {
				if name.as_str().eq_ignore_ascii_case("Set-Cookie") {
					value.to_str().ok()
				} else {
					None
				}
			})
			.collect();
		println!("{:?}", cookies);

		let mut filtered_cookies: Vec<String> = Vec::default();
		for cookie in cookies {
			let spl = cookie.split(";");
			for elem in spl {
				if elem.contains("ApplicationGatewayAffinityCORS")
					|| elem.contains("ApplicationGatewayAffinity")
				{
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

		let discovery_path = format!(
			"https://api.directory.signal.org/v1/discovery/{}",
			ENCLAVE_ID
		);

		let mut req = common_http_headers(
			http::Method::PUT,
			&discovery_path,
			upgraded_auth_header.as_str(),
		)?;

		req = req.header("Content-Type", "application/json; charset=utf-8");
		req = req.header("Content-Length", query_str.len());
		req = req.header("Cookie", resulting_cookie_string);
		let req = req.body(query_str.into_bytes())?;

		let response = self.http_client.request(req).await.map_err(|e| {
			Box::new(SendMessageError::CannotSendDiscoveryReq {
				msg: format!("{:?}", e),
			})
		})?;
		debug!("{:?}", response);

        let response_str = String::from_utf8(response.body().to_vec())?;
		let discovery_response: DiscoveryResponse = serde_json::from_str(&response_str)?;
		let decrypted = discovery_response.decrypt(&att_list)?;
		let uuid = Uuid::from_slice(decrypted.as_slice())?;
		debug!(
			"Successfully decoded discovery response! The recipient's UUID is: {:?}",
			uuid
		);
		Ok(uuid)
	}

	pub async fn retrieve_payment_address(
		&mut self,
		recipient: &AuxinAddress,
	) -> std::result::Result<auxin_protos::PaymentAddress, PaymentAddressRetrievalError> {
		self.ensure_peer_loaded(recipient).await.map_err(|e| {
			PaymentAddressRetrievalError::ErrPeer {
				peer: recipient.clone(),
				err: format!("{:?}", e),
			}
		})?;
		//We may have just grabbed the UUID in ensure_peer_loaded() above, make sure we have a usable address.
		let recipient = self
			.context
			.peer_cache
			.complete_address(recipient)
			.unwrap_or(recipient.clone());

		if let Some(peer) = self.context.peer_cache.get(&recipient) {
			if let Some(profile_key) = &peer.profile_key {
				let mut profile_key_bytes: [u8; PROFILE_KEY_LEN] = [0; PROFILE_KEY_LEN];
				let temp_bytes = base64::decode(profile_key).map_err(|e| {
					PaymentAddressRetrievalError::EncodingError {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					}
				})?;
				profile_key_bytes.copy_from_slice(&(temp_bytes)[0..PROFILE_KEY_LEN]);

				let uuid =
					recipient
						.get_uuid()
						.map_err(|e| PaymentAddressRetrievalError::NoUuid {
							peer: recipient.clone(),
							err: e,
						})?;

				let randomness: [u8; 32] = self.rng.gen();
				let server_secret_params = zkgroup::api::ServerSecretParams::generate(randomness);
				let server_public_params = server_secret_params.get_public_params();
				let randomness: [u8; 32] = self.rng.gen();
				let zk_profile_key = zkgroup::api::profiles::ProfileKey::create(profile_key_bytes);
				let version = zk_profile_key.get_profile_key_version(*uuid.as_bytes());
				let request_context = server_public_params
					.create_profile_key_credential_request_context(
						randomness,
						*uuid.as_bytes(),
						zk_profile_key,
					);
				let request = request_context.get_request();
				let encoded_request = hex::encode(&bincode::serialize(&request).unwrap());

				let version_bytes = bincode::serialize(&version).map_err(|e| {
					PaymentAddressRetrievalError::EncodingError {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					}
				})?;
				let version_string = String::from_utf8_lossy(&version_bytes);

				let get_path = format!(
					"https://textsecure-service.whispersystems.org/v1/profile/{}/{}/{}",
					uuid.to_string(),
					version_string,
					encoded_request
				);

				let unidentified_access = self
					.context
					.get_unidentified_access_for(&recipient, &mut self.rng)
					.map_err(|e| PaymentAddressRetrievalError::UnidentifiedAccess {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					})?;
				let unidentified_access = base64::encode(unidentified_access);
				let req = common_http_headers(
					http::Method::GET,
					&get_path,
					&self.context.identity.make_auth_header(),
				)
				.map_err(|e| PaymentAddressRetrievalError::EncodingError {
					peer: recipient.clone(),
					msg: format!("{:?}", e),
				})?
				.header("Unidentified-Access-Key", unidentified_access)
				.body(Vec::default())
				.map_err(|e| PaymentAddressRetrievalError::EncodingError {
					peer: recipient.clone(),
					msg: format!("{:?}", e),
				})?;
				debug!("Requesitng profile key credential with {:?}", req);
				let response = self.http_client.request(req).await.map_err(|e| {
					PaymentAddressRetrievalError::EncodingError {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					}
				})?;

                let response_str = String::from_utf8(response.body().to_vec())
                    .map_err(|e| PaymentAddressRetrievalError::DecodingError {
                        peer: recipient.clone(),
                        msg: format!("{:?}", e),
                    })?;

				let response_structure: ProfileResponse = serde_json::from_str(&response_str)
					.map_err(|e| PaymentAddressRetrievalError::DecodingError {
						peer: recipient.clone(),
						msg: format!("{:?}", e),
					})?;

				if let Some(address_b64) = &response_structure.payment_address {
					let key = aes_gcm::Key::from_slice(&profile_key_bytes);
					let cipher = Aes256Gcm::new(key);

					let payment_address_bytes = base64::decode(&address_b64).map_err(|e| {
						PaymentAddressRetrievalError::DecodingError {
							peer: recipient.clone(),
							msg: format!("{:?}", e),
						}
					})?;

					//                              Nonce + content + ????
					assert!(payment_address_bytes.len() >= 12 + 16 + 1);

					let mut nonce_bytes: [u8; 12] = [0; 12];
					nonce_bytes.copy_from_slice(&payment_address_bytes[0..12]);

					let nonce = Nonce::from_slice(&nonce_bytes);

					let content_len = payment_address_bytes.len() - nonce_bytes.len();

					let mut content_bytes: Vec<u8> = vec![0; content_len];

					// Reminder that slicing [num..] in Rust gives you from index num to the end of the container.
					content_bytes.copy_from_slice(&payment_address_bytes[nonce_bytes.len()..]);
					let payload = Payload {
						msg: &content_bytes,
						aad: b"",
					};
					let decryption_result = cipher.decrypt(nonce, payload).map_err(|e| {
						PaymentAddressRetrievalError::DecryptingError {
							peer: recipient.clone(),
							msg: format!("{:?}", e),
						}
					})?;

					// 4 bits len - - 32 bit (signed?) integer describing buffer length.
					let max_length = (decryption_result.len() - 4) as i32;
					let mut tag_bytes: [u8; 4] = [0; 4];
					tag_bytes.copy_from_slice(&decryption_result[0..4]);
					let length = i32::from_le_bytes(tag_bytes);
					assert!(length < max_length);
					assert!(length > 0);

					let length = length as usize;
					let mut content_bytes: Vec<u8> = vec![0; length];

					// 4 bytes for length - offset by that. Get "length" bytes affter the length tag itself.
					// The rest is padding.
					content_bytes.copy_from_slice(&decryption_result[4..(length + 4)]);

					let fixed_buf = fix_protobuf_buf(&content_bytes).map_err(|e| {
						PaymentAddressRetrievalError::DecodingError {
							peer: recipient.clone(),
							msg: format!("{:?}", e),
						}
					})?;
					let mut reader = protobuf::CodedInputStream::from_bytes(&fixed_buf);
					let payment_address: auxin_protos::PaymentAddress = reader
						.read_message()
						.map_err(|e| PaymentAddressRetrievalError::DecodingError {
							peer: recipient.clone(),
							msg: format!("{:?}", e),
						})?;
					return Ok(payment_address);
				};
				return Err(PaymentAddressRetrievalError::NoPaymentAddressForUser {
					peer: recipient.clone(),
				});
			} else {
				return Err(PaymentAddressRetrievalError::NoProfileKey {
					peer: recipient.clone(),
				});
			}
		} else {
			return Err(PaymentAddressRetrievalError::NoPeer {
				peer: recipient.clone(),
			});
		}
	}
	pub async fn retrieve_attachment(&self, attachment: &AttachmentPointer) -> std::result::Result<EncryptedAttachment, AttachmentDownloadError> {
		//TODO: Test to see if there is any time when we need to use a different CDN address.
		download::retrieve_attachment(attachment.clone(), self.http_client.clone(), SIGNAL_CDN).await
	}

	pub async fn request_attachment_id(&self) -> std::result::Result<PreUploadToken, AttachmentUploadError> { 

		let auth = self.context.identity.make_auth_header();

		attachment::upload::request_attachment_token(self.http_client.clone(),
														("Authorization", auth.as_str()) ).await
	}

	pub fn get_http_client(&self) -> &N::C {
		return &self.http_client;
	}
	pub fn get_http_client_mut(&mut self) -> &mut N::C {
		return &mut self.http_client;
	}
}

impl<R, N, S> Drop for AuxinApp<R, N, S>
where
	R: RngCore + CryptoRng,
	N: AuxinNetManager,
	S: AuxinStateManager,
{
	fn drop(&mut self) {
		// Make sure all data gets saved first.
		self.state_manager
			.save_entire_context(&self.context)
			.unwrap();
		self.state_manager.flush(&self.context).unwrap();
	}
}

pub use crate::receiver::{AuxinReceiver, ReceiveError};
