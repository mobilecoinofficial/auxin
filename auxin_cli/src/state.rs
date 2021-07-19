use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;
use std::fs::read_dir;

use auxin::{AuxinConfig, PROFILE_KEY_LEN};
use auxin::LocalIdentity;
use auxin::Result;
use auxin::address::{AuxinAddress, AuxinDeviceAddress, E164};
use auxin::state::PeerRecordStructure;

use libsignal_protocol::{IdentityKey, IdentityKeyPair, IdentityKeyStore, InMemIdentityKeyStore, InMemPreKeyStore, InMemSenderKeyStore, InMemSessionStore, InMemSignedPreKeyStore, PreKeyRecord, PreKeyStore, PrivateKey, ProtocolAddress, PublicKey, SenderCertificate, SessionRecord, SessionStore, SignedPreKeyRecord, SignedPreKeyStore};
use log::{debug, warn};
use rand::rngs::OsRng;
use uuid::Uuid;
use custom_error::custom_error;
use serde::{Deserialize, Serialize};

use crate::Context;

/// Loads the needed information for a LocalIdentity from a json file - intended to be compatible with Libsingal-cli
pub fn load_signal_cli_user(base_dir: &str, our_phone_number: &E164) -> Result<serde_json::Value> {
    let mut identity_dir = String::from_str(base_dir)?;
	let f = std::fs::canonicalize(base_dir);
	println!("{:?}", f);
    if !base_dir.ends_with("/") {
        identity_dir.push_str("/");
    }

    let mut identity_file_path = identity_dir.clone();
    identity_file_path.push_str(our_phone_number.as_str());

    let file = File::open(identity_file_path)?;
    return Ok(serde_json::from_reader(file)?);
}

custom_error!{ pub ErrBuildIdent
    MissingUsername{val:serde_json::Value} = "No phone number (the field will be named \"username\") found when trying to build a LocalIdentity from json structure. Structure contains: {val}",
    MissingUuid{phone_number:E164} = "No uuid found when trying to build a LocalIdentity from json structure for user: {phone_number}.",
    DeviceIdNotUInt{val:serde_json::Value} = "Tried to use {val} as the Device ID when trying to build a LocalIdentity from json structure. Requires unsigned int.",
    MissingRegistrationId{phone_number:E164} = "No registration id found when trying to build a LocalIdentity from json structure for user: {phone_number}.",
    MissingPassword{phone_number:E164} = "No password found when trying to build a LocalIdentity from json structure for user: {phone_number}.",
    MissingProfileKey{phone_number:E164} = "No profile key found when trying to build a LocalIdentity from json structure for user: {phone_number}.",
    InvalidProfileKey{num_bytes:usize} = "Invalid profile key! Profile keys are 32 bytes, the base-64 string decoded to {num_bytes} bytes instead.",
    MissingPrivateKey{phone_number:E164} = "No private key found when trying to build a LocalIdentity from json structure for user: {phone_number}.",
    MissingPublicKey{phone_number:E164} = "No public key found when trying to build a LocalIdentity from json structure for user: {phone_number}.",
}

/// Builds a LocalIdentity from the json structure loaded by load_signal_cli_user() - intended to be compatible with Libsingal-cli
pub fn local_identity_from_json(val: &serde_json::Value) -> Result<LocalIdentity> {

    //Phone number.
    let phone_number = val.get("username").ok_or(ErrBuildIdent::MissingUsername { val: val.clone() })?;
    let phone_number = phone_number.as_str().ok_or(ErrBuildIdent::MissingUsername { val: val.clone() })?;
    
    //UUID
    let our_uuid = val.get("uuid").ok_or(ErrBuildIdent::MissingUuid { phone_number: phone_number.clone().to_string() })?;
    let our_uuid = our_uuid.as_str().ok_or(ErrBuildIdent::MissingUuid { phone_number: phone_number.clone().to_string() })?;
    let our_uuid = Uuid::from_str(our_uuid)?;

    //Password
    let password = val.get("password").ok_or(ErrBuildIdent::MissingPassword { phone_number: phone_number.clone().to_string() })?;
    let password = password.as_str().ok_or(ErrBuildIdent::MissingPassword { phone_number: phone_number.clone().to_string() })?.to_string();

    //Registration ID
    let registration_id = val.get("registrationId").ok_or(ErrBuildIdent::MissingRegistrationId { phone_number: phone_number.clone().to_string() })?;
    let registration_id = registration_id.as_u64().ok_or(ErrBuildIdent::MissingRegistrationId { phone_number: phone_number.clone().to_string() })?;

    //Profile key
    let profile_key = val.get("profileKey").ok_or(ErrBuildIdent::MissingProfileKey { phone_number: phone_number.clone().to_string() })?;
    let profile_key = profile_key.as_str().ok_or(ErrBuildIdent::MissingProfileKey { phone_number: phone_number.clone().to_string() })?.to_string();
    let profile_key = base64::decode(profile_key)?;
    if profile_key.len() != PROFILE_KEY_LEN { //Sanity check.
        return Err(Box::new(ErrBuildIdent::InvalidProfileKey { num_bytes: profile_key.len() }));
    }
    let mut decoded_profile_key: [u8; PROFILE_KEY_LEN] = [0;PROFILE_KEY_LEN]; 
    for i in 0..PROFILE_KEY_LEN { 
        decoded_profile_key[i] = profile_key[i];
    }

    //Device ID
    let device_id = match val.get("deviceId") { 
        Some(id) => { 
            id.as_u64().ok_or(ErrBuildIdent::DeviceIdNotUInt{val: id.clone()})?
        },
        None => 1, //Default device ID is 1. 
    } as u32;

    //Private key 
    let private_key = val.get("identityPrivateKey").ok_or(ErrBuildIdent::MissingPrivateKey { phone_number: phone_number.clone().to_string() })?;
    let private_key = private_key.as_str().ok_or(ErrBuildIdent::MissingPrivateKey { phone_number: phone_number.clone().to_string() })?.to_string();
    let private_key = base64::decode(private_key)?;
    let private_key = PrivateKey::deserialize(private_key.as_slice())?;

    //Public key 
    let public_key = val.get("identityKey").ok_or(ErrBuildIdent::MissingPublicKey { phone_number: phone_number.clone().to_string() })?;
    let public_key = public_key.as_str().ok_or(ErrBuildIdent::MissingPublicKey { phone_number: phone_number.clone().to_string() })?.to_string();
    let public_key = base64::decode(public_key)?;
    let public_key = PublicKey::deserialize(public_key.as_slice())?;

    let our_address = AuxinDeviceAddress { 
        address: AuxinAddress::Both(phone_number.clone().to_string(), our_uuid),
        device_id,
    };

    Ok(LocalIdentity {
        our_address,
        password,
        our_profile_key: decoded_profile_key,
        our_identity_keys: IdentityKeyPair::new(IdentityKey::new(public_key), private_key),
        our_reg_id: registration_id as u32,
    })
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PeerIdentity {
	pub identity_key : String,
	pub trust_level : Option<i32>,
	pub added_timestamp : Option<u64>,
}

/// Load any identity keys for known peers (recipients) present in our protocol store. These end up in identity_store.known_keys
#[allow(unused_must_use)]
pub async fn load_known_peers(
	our_id: &String,
	base_dir: &str,
	recipients: &PeerRecordStructure,
	identity_store: &mut InMemIdentityKeyStore,
	ctx: &libsignal_protocol::Context,
) -> Result<()> {
	let mut our_path = base_dir.clone().to_string();
	our_path.push_str("/");
	our_path.push_str(our_id);
	our_path.push_str(".d/");
	let mut known_peers_path = our_path.clone();
	known_peers_path.push_str("identities/");

	for recip in recipients.peers.iter() {
		let mut this_peer_path = known_peers_path.clone();
		this_peer_path.push_str(format!("{}", recip.id).as_str());
		debug!("Attempting to load peer identity from {}", this_peer_path);
		if Path::new(this_peer_path.as_str()).exists() { 
			let mut peer_string = String::default();
			debug!("Loading peer identity store from path: {}", this_peer_path);

			{
				File::open(&this_peer_path)?.read_to_string(&mut peer_string)?;
			}

			let peer_identity: PeerIdentity = serde_json::from_str(peer_string.as_str())?;
			let decoded_key: Vec<u8> = base64::decode(peer_identity.identity_key)?;
			let id_key = IdentityKey::decode(decoded_key.as_slice())?;
			for i in recip.device_ids_used.iter() {
				let addr = ProtocolAddress::new(recip.uuid.to_string(), *i);
				identity_store.save_identity(&addr, &id_key, *ctx);
				let addr = ProtocolAddress::new(recip.number.clone(), *i);
				identity_store.save_identity(&addr, &id_key, *ctx);
				debug!("Loaded identity key {:?} for known peer {:?}", id_key, addr);
			}
		}
	}

	Ok(())
}

pub async fn load_sessions(
	our_id: &String,
	base_dir: &str,
	ctx: &libsignal_protocol::Context,
) -> Result<(InMemSessionStore, PeerRecordStructure)> {
	let mut our_path = base_dir.clone().to_string();
	our_path.push_str("/");
	our_path.push_str(our_id);
	our_path.push_str(".d/");
	let mut recipients_path = our_path.clone();
	recipients_path.push_str("recipients-store");

	let mut recipients_string = String::default();
	debug!("Loading recipients store from path: {}", recipients_path);

	//----Load session metadata

	//Load recipients file.
	let mut recipient_structure: PeerRecordStructure = match File::open(&recipients_path) {
		Ok(mut file) => {
			file.read_to_string(&mut recipients_string)?;
			let mut recip: PeerRecordStructure = serde_json::from_str(recipients_string.as_str())?;
			recip.peers.sort();
			recip
		}
		Err(error) => { 
			debug!("Unable to open recipients-store: {:?}, generating an empty recipients structure", error);
			PeerRecordStructure {
				peers: Vec::default(),
				last_id: 0,
			} 
		}
	};
	
	debug!("Recipient structure loaded: {:?}", recipient_structure);

	//---Look for recorded sessions in our sessions directory.

	let mut session_path = our_path.clone();
	session_path.push_str("sessions/");
	let directory_contents = read_dir(session_path.clone());

	let session_store = match directory_contents {
		Ok(directory_contents) => { 
			let mut session_file_list: Vec<String> = Vec::default();
			for item in directory_contents {
				match item {
					Ok(inner) => match inner.file_type() {
						Ok(ty) => {
							if ty.is_file() {
								session_file_list.push(String::from(inner.file_name().to_str().unwrap()));
							}
						}
						Err(e) => {
							warn!("Suppressing directory traversal error: {}", e);
						}
					},
					Err(e) => {
						warn!("Suppressing directory traversal error: {}", e);
					}
				}
			}

			//----Actually load our session store proper

			let mut session_store = InMemSessionStore::default();

			for file_name in session_file_list {
				let mut file_path = session_path.clone();
				file_path.push_str(file_name.as_str());
				let (recipient_id, recipient_device_id) = file_name.split_once("_").unwrap();
				//Address retrieval from oru previously-built session list
				//TODO: More informative error handling.
				let recipient_id_num: usize = recipient_id.parse::<usize>()?;
				debug!("Loading a recipient. Recipient ID number {:?}", recipient_id_num);
				let recip = recipient_structure
					.peers
					.iter_mut()
					.find(|r| r.id == recipient_id_num.clone() as u64)
					.unwrap();
				let device_id_num: u32 = recipient_device_id.parse::<u32>()?;
				//NOTE RECIPIENT ADDRESS IS USING UUID
				let recipient_address = ProtocolAddress::new(recip.uuid.to_string().clone(), device_id_num);

				//Let's also build some extra cached information we keep around for convenience!
				recip.device_ids_used.push(device_id_num);

				debug!("Recipient {:?} with device number {:?} has protocol address {:?}", recipient_id_num, recipient_device_id, recipient_address);
				//Open session file.
				let mut buffer = Vec::new();
				let mut f = File::open(file_path.as_str())?;
				f.read_to_end(&mut buffer)?;
				//Call into libsignal-client-rs's decoding generated by protobuf
				let record = SessionRecord::deserialize(buffer.as_slice())?;

				debug!("Loaded {} bytes from {}", buffer.len(), &file_path );

				//Store as UUID
				session_store.store_session(&recipient_address, &record, *ctx).await?;

				
			}
			session_store
		},
		Err(e) => {
			debug!("Could not open directory: {:?}, generating new session store.", e);
			InMemSessionStore::new()
		}
	};
	Ok((session_store, recipient_structure))
}

pub async fn load_prekeys(our_id: &String, base_dir: &str, ctx: &libsignal_protocol::Context) 
				-> Result<(InMemPreKeyStore, InMemSignedPreKeyStore)> {

	let mut pre_key_store = InMemPreKeyStore::default();
	let mut signed_pre_key_store = InMemSignedPreKeyStore::default();

	//Figure out some directories.
	let mut our_path = base_dir.to_string();
	our_path.push_str("/");
	our_path.push_str(our_id);
	our_path.push_str(".d/");
	let mut pre_keys_path = our_path.clone();
	pre_keys_path.push_str("pre-keys/");
	let mut signed_pre_keys_path = our_path.clone();
	signed_pre_keys_path.push_str("signed-pre-keys/");

	//Iterate through files in pre_keys_path
	let directory_contents = read_dir(pre_keys_path.clone())?;

	let mut pre_key_file_list: Vec<String> = Vec::default();

	for item in directory_contents {
		match item {
			Ok(inner) => match inner.file_type() {
				Ok(ty) => {
					if ty.is_file() {
						pre_key_file_list.push(String::from(inner.file_name().to_str().unwrap()));
					}
				}
				Err(e) => {
					warn!("Suppressing directory traversal error: {}", e);
				}
			},
			Err(e) => {
				warn!("Suppressing directory traversal error: {}", e);
			}
		}
	}

	for file_name in pre_key_file_list {
		let mut file_path = pre_keys_path.clone();
		file_path.push_str(file_name.as_str());
		//These files should be named 0, 1, 2, etc...
		let _id: u32 = file_name.parse()?;
		
		let mut buffer = Vec::new();
		let mut f = File::open(file_path.as_str())?;
		f.read_to_end(&mut buffer)?;

		let record = PreKeyRecord::deserialize(buffer.as_slice())?;

		pre_key_store.save_pre_key(record.id()?, &record, *ctx).await?;
	}

	//Iterate through files in signed_pre_keys_path
	let directory_contents = read_dir(signed_pre_keys_path.clone())?;

	let mut signed_pre_key_file_list: Vec<String> = Vec::default();

	for item in directory_contents {
		match item {
			Ok(inner) => match inner.file_type() {
				Ok(ty) => {
					if ty.is_file() {
						signed_pre_key_file_list.push(String::from(inner.file_name().to_str().unwrap()));
					}
				}
				Err(e) => {
					warn!("Suppressing directory traversal error: {}", e);
				}
			},
			Err(e) => {
				warn!("Suppressing directory traversal error: {}", e);
			}
		}
	}

	for file_name in signed_pre_key_file_list {
		let mut file_path = signed_pre_keys_path.clone();
		file_path.push_str(file_name.as_str());
		//These files should be named 0, 1, 2, etc...
		let id: u32 = file_name.parse()?;
		
		let mut buffer = Vec::new();
		let mut f = File::open(file_path.as_str())?;
		f.read_to_end(&mut buffer)?;

		let record = SignedPreKeyRecord::deserialize(buffer.as_slice())?;
		
		debug!("Loaded a signed pre-key with ID {:?}", id);
		signed_pre_key_store.save_signed_pre_key(id, &record, *ctx).await?;
	}

	Ok((pre_key_store, signed_pre_key_store))
}

pub async fn save_all(context: &Context, base_dir: &str) -> Result<()> {
	let our_id: String = context.our_identity.our_address.get_phone_number()?.clone();
	//Figure out some directories.
	let mut our_path = base_dir.to_string();
	our_path.push_str("/");
	our_path.push_str(our_id.as_str());
	our_path.push_str(".d/");
	
	let mut pre_keys_path = our_path.clone();
	pre_keys_path.push_str("pre-keys/");
	let mut signed_pre_keys_path = our_path.clone();
	signed_pre_keys_path.push_str("signed-pre-keys/");

	let mut recipients_path = our_path.clone();
	recipients_path.push_str("recipients-store");

	let mut session_path = our_path.clone();
	session_path.push_str("sessions/");

	let mut _known_peers_path = our_path.clone();
	_known_peers_path.push_str("identities/");
	
	//Build a list of all recipient IDs and all recipient-device addresses in our store.
	let mut addresses : Vec<(u64, ProtocolAddress)> = Vec::default();
	for r in &context.peer_cache.peers { 
		for i in r.device_ids_used.iter() {
			//MUST USE UUID
			addresses.push( (r.id, ProtocolAddress::new(r.uuid.to_string().clone(), *i)) );
		}
	}

	for address in addresses.iter() { 
		let mut file_path = session_path.clone();
		let session_file_name = format!("{}_{}", address.0, address.1.device_id());
		file_path.push_str(session_file_name.as_str());

		let mut file = OpenOptions::new()
			.truncate(true)
			.write(true)
			.create(true)
			.open(file_path.clone())?;
			
		
		debug!("Session lookup for {:?}", address);
		let session = context.session_store.load_session(&address.1, context.signal_ctx).await?;
		let session = match session { 
			Some(s) => s, 
			None => { 
				//todo: Better error handling here.
				continue;
			},
		};
		let bytes = session.serialize()?;
		file.write_all(bytes.as_slice())?;
		file.flush()?;
		debug!("Session file for {} written: {}", &address.1.name(), file_path.clone());
	}

	// Save recipient store: 
	let json_recipient_structure = serde_json::to_string_pretty(&context.peer_cache)?;
	//debug!("Recipient structure {}", json_recipient_structure);

	let mut file = OpenOptions::new()
		.truncate(true)
		.write(true)
		.create(true)
		.open(recipients_path.clone())?;

	file.write_all(json_recipient_structure.as_bytes())?;
	file.flush()?;
	//Ensure file is closed ASAP.
	drop(file);

	/*for addr in addresses {
		let ident = identity_store.get_identity(&addr.1, *ctx).await?;
		if let Some(ident) = ident { 
			let mut this_peer_path = known_peers_path.clone();
			this_peer_path.push_str(format!("{}", addr.0).as_str());
		}
	}*/

	Ok(())
}
pub async fn make_context(base_dir: &str, local_identity: LocalIdentity, sender_cert: SenderCertificate, config: AuxinConfig, ctx: libsignal_protocol::Context) -> Result<Context> {
	let our_phone_number = local_identity.our_address.address.get_phone_number().unwrap();

	let mut identity_store = InMemIdentityKeyStore::new(local_identity.our_identity_keys.clone(), local_identity.our_reg_id);
	
	//Load cached peers and sessions.
	let (sessions, peers) = load_sessions(&our_phone_number, base_dir, &ctx).await?;
	//Load identity keys we saved for peers previously. Writes to the identity store.
	load_known_peers(&our_phone_number, base_dir, &peers, &mut identity_store, &ctx).await?;
	let (pre_keys, signed_pre_keys) = load_prekeys(&our_phone_number, base_dir, &ctx).await?;

	Ok(Context {
		our_identity: local_identity,
		our_sender_certificate: sender_cert,
		peer_cache: peers,
		session_store: sessions,
		pre_key_store: pre_keys,
		signed_pre_key_store: signed_pre_keys,
		identity_store: identity_store,
		sender_key_store: InMemSenderKeyStore::new(),
		rng: OsRng,
		config: config,
		signal_ctx: ctx,
		report_as_online: false,
	})
}