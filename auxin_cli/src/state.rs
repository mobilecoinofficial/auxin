// Copyright (c) 2021 MobileCoin Inc.
// Copyright (c) 2021 Emily Cultip
//! Manages signal-cli state for auxin

use std::{
	convert::TryFrom,
	fs,
	fs::{File, OpenOptions},
	io::{BufReader, BufWriter, Read, Write},
	path::{Path, PathBuf},
};

use auxin::{
	address::{AuxinAddress, AuxinDeviceAddress, E164},
	generate_timestamp,
	state::{AuxinStateManager, PeerIdentity, PeerRecordStructure, PeerStore},
	AuxinConfig, AuxinContext, LocalIdentity, Result, SignalCtx, PROFILE_KEY_LEN,
};

use custom_error::custom_error;
use futures::executor::block_on;
use libsignal_protocol::{
	IdentityKey, IdentityKeyPair, IdentityKeyStore, InMemIdentityKeyStore, InMemPreKeyStore,
	InMemSenderKeyStore, InMemSessionStore, InMemSignedPreKeyStore, PreKeyRecord, PreKeyStore,
	PrivateKey, ProtocolAddress, PublicKey, SessionRecord, SessionStore, SignedPreKeyRecord,
	SignedPreKeyStore,
};
use log::{debug, error, info, warn};
use protobuf::CodedInputStream;
use serde::{Deserialize, Serialize};
use serde_json::{from_reader, to_value};
use uuid::Uuid;

use crate::Context;

/// The on-disk json format, as used by signal-cli
///
/// Signal-cli implements this format [here]
///
/// [here]: <https://github.com/AsamK/signal-cli/blob/v0.10.2/lib/src/main/java/org/asamk/signal/manager/storage/SignalAccount.java>
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct LocalIdentityJson {
	/// Currently supported is version is `3`
	#[serde(default)]
	version: u64,

	/// Signal phone number
	// TODO(Diana): Allegedly sometimes a UUID? When? Both? LocalIdentity claims this.
	username: Option<E164>,

	/// Signal account UUID
	uuid: Option<Uuid>,

	/// Signal account password?
	password: Option<String>,

	// u32 should be fine? signal-cli uses java ints which are only 32bits
	registration_id: Option<u32>,

	/// Signal profile key. Used for sealed sender?
	profile_key: Option<String>,

	/// Device ID. Defaults to 1 allegedly?
	// TODO(Diana): Pretty sure this should always exist. signal-cli unconditionally writes this out.
	// See https://github.com/AsamK/signal-cli/blob/166bec0f8d2f3291dde4f30964692b550ff8ac40/lib/src/main/java/org/asamk/signal/manager/storage/SignalAccount.java#L737
	device_id: Option<u32>,

	/// Private key
	#[serde(rename = "identityPrivateKey")]
	private_key: Option<String>,

	/// Public key
	#[serde(rename = "identityKey")]
	public_key: Option<String>,
}

/// Attempts to convert the on-disk format to our [`LocalIdentity`] structure
///
/// Preserves nice error information about missing fields.
impl TryFrom<LocalIdentityJson> for LocalIdentity {
	type Error = Box<dyn std::error::Error>;

	fn try_from(val: LocalIdentityJson) -> std::result::Result<Self, Self::Error> {
		let phone_number = val
			.username
			.as_ref()
			.ok_or(ErrBuildIdent::MissingUsername {
				val: to_value(val.clone()).unwrap(),
			})?
			.clone();
		let uuid = val.uuid.ok_or(ErrBuildIdent::MissingUuid {
			phone_number: phone_number.clone(),
		})?;
		let profile_key =
			base64::decode(val.profile_key.ok_or(ErrBuildIdent::MissingProfileKey {
				phone_number: phone_number.clone(),
			})?)?;
		let profile_key = <[u8; PROFILE_KEY_LEN]>::try_from(profile_key)
			.map_err(|v| ErrBuildIdent::InvalidProfileKey { num_bytes: v.len() })?;
		let device_id = val.device_id.unwrap_or(1);
		let private_key = val.private_key.ok_or(ErrBuildIdent::MissingPrivateKey {
			phone_number: phone_number.clone(),
		})?;
		let private_key = base64::decode(private_key)?;
		let private_key = PrivateKey::deserialize(private_key.as_slice())?;
		let public_key = val.public_key.ok_or(ErrBuildIdent::MissingPublicKey {
			phone_number: phone_number.clone(),
		})?;
		let public_key = base64::decode(public_key)?;
		let public_key = PublicKey::deserialize(public_key.as_slice())?;

		let address = AuxinDeviceAddress {
			address: AuxinAddress::Both(phone_number.clone(), uuid),
			device_id,
		};

		Ok(LocalIdentity {
			address,
			password: val.password.ok_or(ErrBuildIdent::MissingPassword {
				phone_number: phone_number.clone(),
			})?,
			profile_key,
			identity_keys: IdentityKeyPair::new(IdentityKey::new(public_key), private_key),
			reg_id: val
				.registration_id
				.ok_or(ErrBuildIdent::MissingRegistrationId { phone_number })?,
		})
	}
}

custom_error! { pub ErrBuildIdent
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

/// Load any identity keys for known peers (recipients) present in our protocol store.
///
/// These end up in identity_store.known_keys
// #[allow(unused_must_use)]
// TODO(Diana): Why is this async. No awaits in here.
pub async fn load_known_peers(
	our_id: &E164,
	data_dir: &Path,
	recipients: &mut PeerRecordStructure,
	identity_store: &mut InMemIdentityKeyStore,
	ctx: libsignal_protocol::Context,
) -> Result<()> {
	let our_path = data_dir.join(&our_id).with_extension("d");
	let known_peers_path = our_path.join("identities");

	for recip in recipients.peers.iter_mut() {
		let this_peer_path = known_peers_path.join(recip.id.to_string());

		debug!(
			"Attempting to load peer identity from {}",
			this_peer_path.display()
		);

		if this_peer_path.exists() {
			debug!(
				"Loading peer identity store from path: {}",
				this_peer_path.display()
			);

			let peer_identity: PeerIdentity =
				from_reader(BufReader::new(File::open(&this_peer_path)?))?;

			let decoded_key: Vec<u8> = base64::decode(&peer_identity.identity_key)?;
			let id_key = IdentityKey::decode(decoded_key.as_slice())?;
			for i in recip.device_ids_used.iter() {
				if let Some(uuid) = &recip.uuid {
					let addr = ProtocolAddress::new(uuid.to_string(), *i);
					// TODO(Diana): Why are we ignoring these errors?
					let _ = identity_store.save_identity(&addr, &id_key, ctx);
				}
				if let Some(number) = &recip.number {
					let addr = ProtocolAddress::new(number.clone(), *i);
					// TODO(Diana): Why are we ignoring these errors?
					let _ = identity_store.save_identity(&addr, &id_key, ctx);
				}
			}
			recip.identity = Some(peer_identity);
		}
	}

	Ok(())
}

/// Load cached peers and sessions from signal-cli
pub async fn load_sessions(
	our_phone: &E164,
	data_dir: &Path,
	ctx: libsignal_protocol::Context,
) -> Result<(InMemSessionStore, PeerRecordStructure)> {
	let our_path = data_dir.join(our_phone).with_extension("d");
	let recipients_path = our_path.join("recipients-store");

	debug!(
		"Loading recipients store from path: {}",
		recipients_path.display()
	);

	//----Load session metadata

	//Load recipients file.
	let mut recipient_structure: PeerRecordStructure = match File::open(&recipients_path) {
		Ok(file) => {
			let mut recip: PeerRecordStructure = from_reader(BufReader::new(file))?;
			recip.peers.sort();
			recip
		}
		Err(error) => {
			debug!(
				"Unable to open recipients-store: {}, generating an empty recipients structure",
				error
			);
			PeerRecordStructure {
				peers: Vec::default(),
				last_id: 0,
			}
		}
	};

	//---Look for recorded sessions in our sessions directory.

	let session_path = our_path.join("sessions");
	let directory_contents = session_path.read_dir();

	let session_store = match directory_contents {
		Ok(directory_contents) => {
			let mut session_file_list: Vec<String> = Vec::default();
			for item in directory_contents {
				match item {
					Ok(inner) => match inner.file_type() {
						Ok(ty) => {
							if ty.is_file() {
								session_file_list
									.push(String::from(inner.file_name().to_str().unwrap()));
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
				let file_path = session_path.join(&file_name);

				let (recipient_id, recipient_device_id) = file_name.split_once('_').unwrap();
				//Address retrieval from our previously-built session list
				//TODO: More informative error handling.
				// TODO(Diana): Why usize?
				let recipient_id_num: usize = recipient_id.parse::<usize>()?;
				debug!(
					"Loading a recipient. Recipient ID number {:?}",
					recipient_id_num
				);
				let recip = recipient_structure
					.peers
					.iter_mut()
					.find(|r| r.id == recipient_id_num as u64)
					.unwrap();
				let device_id_num: u32 = recipient_device_id.parse::<u32>()?;

				if let Some(uuid) = recip.uuid {
					//NOTE RECIPIENT ADDRESS IS USING UUID
					let recipient_address =
						ProtocolAddress::new(uuid.to_string().clone(), device_id_num);

					//Let's also build some extra cached information we keep around for convenience!
					recip.device_ids_used.insert(device_id_num);

					//Open session file.
					let mut buffer = Vec::new();
					let mut f = BufReader::new(File::open(&file_path)?);
					f.read_to_end(&mut buffer)?;
					//Call into libsignal-client-rs's decoding generated by protobuf
					let record = SessionRecord::deserialize(buffer.as_slice())?;

					debug!("Loaded {} bytes from {}", buffer.len(), file_path.display());

					//Store the registration ID if we've got it.
					if let Ok(reg_id) = record.remote_registration_id() {
						recip.registration_ids.insert(device_id_num, reg_id);
					} else {
						debug!("Could not get registration ID from recipient_id {} device_id {}. Has current session: {}", recipient_id_num, device_id_num, record.has_current_session_state());
					}

					//Store as UUID
					session_store
						.store_session(&recipient_address, &record, ctx)
						.await?;
				} else {
					warn!(
						"No UUID for {:?}, cannot use existing session file.",
						&recip.number
					);
				}
			}
			session_store
		}
		Err(e) => {
			debug!(
				"Could not open directory: {}, generating new session store.",
				e
			);
			InMemSessionStore::new()
		}
	};
	Ok((session_store, recipient_structure))
}

pub async fn load_prekeys(
	our_phone: &E164,
	data_dir: &Path,
	ctx: libsignal_protocol::Context,
) -> Result<(InMemPreKeyStore, InMemSignedPreKeyStore)> {
	let mut pre_key_store = InMemPreKeyStore::default();
	let mut signed_pre_key_store = InMemSignedPreKeyStore::default();

	//Figure out some directories.
	let our_path = data_dir.join(our_phone).with_extension("d");
	let pre_keys_path = our_path.join("pre-keys");
	let signed_pre_keys_path = our_path.join("signed-pre-keys");

	//Iterate through files in pre_keys_path
	if pre_keys_path.exists() {
		let directory_contents = pre_keys_path.read_dir()?;

		let mut pre_key_file_list: Vec<String> = Vec::default();

		for item in directory_contents {
			match item {
				Ok(inner) => match inner.file_type() {
					Ok(ty) => {
						if ty.is_file() {
							pre_key_file_list
								.push(String::from(inner.file_name().to_str().unwrap()));
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
			let file_path = pre_keys_path.join(&file_name);

			//These files should be named 0, 1, 2, etc...
			let _id: u32 = file_name.parse()?;

			let mut buffer = Vec::new();
			let mut f = BufReader::new(File::open(file_path)?);
			f.read_to_end(&mut buffer)?;

			let record = PreKeyRecord::deserialize(buffer.as_slice())?;

			pre_key_store
				.save_pre_key(record.id()?, &record, ctx)
				.await?;
		}
	}

	if signed_pre_keys_path.exists() {
		//Iterate through files in signed_pre_keys_path
		let directory_contents = signed_pre_keys_path.read_dir()?;

		let mut signed_pre_key_file_list: Vec<String> = Vec::default();

		for item in directory_contents {
			match item {
				Ok(inner) => match inner.file_type() {
					Ok(ty) => {
						if ty.is_file() {
							signed_pre_key_file_list
								.push(String::from(inner.file_name().to_str().unwrap()));
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
			let file_path = signed_pre_keys_path.join(&file_name);

			//These files should be named 0, 1, 2, etc...
			let id: u32 = file_name.parse()?;

			let mut buffer = Vec::new();
			let mut f = BufReader::new(File::open(file_path)?);
			f.read_to_end(&mut buffer)?;

			let record = SignedPreKeyRecord::deserialize(buffer.as_slice())?;

			debug!("Loaded a signed pre-key with ID {:?}", id);
			signed_pre_key_store
				.save_signed_pre_key(id, &record, ctx)
				.await?;
		}
	}

	Ok((pre_key_store, signed_pre_key_store))
}

pub async fn make_context(
	data_dir: &Path,
	local_identity: LocalIdentity,
	config: AuxinConfig,
) -> Result<Context> {
	let our_phone_number = local_identity.address.address.get_phone_number().unwrap();

	let mut identity_store =
		InMemIdentityKeyStore::new(local_identity.identity_keys, local_identity.reg_id);

	//Load cached peers and sessions.
	let (sessions, mut peers) = load_sessions(our_phone_number, data_dir, None).await?;

	//Load identity keys we saved for peers previously. Writes to the identity store.
	load_known_peers(
		our_phone_number,
		data_dir,
		&mut peers,
		&mut identity_store,
		None,
	)
	.await?;
	let (pre_keys, signed_pre_keys) = load_prekeys(our_phone_number, data_dir, None).await?;

	Ok(Context {
		identity: local_identity,
		sender_certificate: None,
		peer_cache: peers,
		session_store: sessions,
		pre_key_store: pre_keys,
		signed_pre_key_store: signed_pre_keys,
		identity_store,
		sender_key_store: InMemSenderKeyStore::new(),
		config,
		report_as_online: false,
		ctx: SignalCtx::default(),
	})
}

/// Bridge between signal-cli state and auxin state
pub struct StateManager {
	/// Signal-cli data directory
	data_dir: PathBuf,
}

impl StateManager {
	/// Create a new state using the supplied state directory
	pub fn new(state_dir: &str) -> Self {
		StateManager {
			data_dir: Path::new(state_dir).join("data"),
		}
	}

	/// Used in tests
	#[cfg(test)]
	fn new_test(data_dir: PathBuf) -> Self {
		StateManager { data_dir }
	}

	/// Get path to signal-cli protocol state, `<phone_number>.d`
	fn get_protocol_store_path(&self, context: &AuxinContext) -> PathBuf {
		// TODO(Diana): Phone numbers, UUIDs, usernames, unwrap.
		let our_id = context.identity.address.get_phone_number().unwrap();
		//Figure out some directories.
		self.data_dir.join(our_id).with_extension("d")
	}
}

/// Auxin state, compatible with signal-cli
impl AuxinStateManager for StateManager {
	/// Load the local identity for `phone_number` from signal-cli
	///
	/// In signal_cli's protocol store structure,
	/// this comes from the file with a name which is your phone number inside the "data" directory.
	fn load_local_identity(&mut self, phone_number: &E164) -> crate::Result<LocalIdentity> {
		let file = File::open(self.data_dir.join(phone_number))?;
		from_reader::<_, LocalIdentityJson>(BufReader::new(file))?.try_into()
	}

	fn load_context(
		&mut self,
		credentials: &LocalIdentity,
		config: AuxinConfig,
	) -> crate::Result<AuxinContext> {
		// TODO(Diana): Why so much async in this file for a sync interface??
		return block_on(make_context(&self.data_dir, credentials.clone(), config));
	}

	fn save_peer_sessions(
		&mut self,
		peer: &AuxinAddress,
		context: &AuxinContext,
	) -> crate::Result<()> {
		info!(
			"Start of auxin_cli's save_peer_sessions() at {}",
			generate_timestamp()
		);
		let peer = &context
			.peer_cache
			.complete_address(peer)
			.unwrap_or_else(|| peer.clone());

		let peer_record = match context.peer_cache.get(peer) {
			Some(a) => a,
			// We do not need to save what is not there.
			None => {
				return Ok(());
			}
		};

		//Figure out some directories.
		let our_path = self.get_protocol_store_path(context);
		let session_path = our_path.join("sessions");
		let known_peers_path = our_path.join("identities");

		if !session_path.exists() {
			std::fs::create_dir(&session_path)?;
		}
		if !known_peers_path.exists() {
			std::fs::create_dir(&known_peers_path)?;
		}

		for device_id in peer_record.device_ids_used.iter() {
			//MUST USE UUID
			if let Some(uuid) = peer_record.uuid {
				let address = ProtocolAddress::new(uuid.to_string().clone(), *device_id);

				let file_path = session_path.join(format!("{}_{}", peer_record.id, device_id));
				let file_bk_path = file_path.with_extension("bk");

				if file_bk_path.exists() {
					error!(
						"Working copy of session store {} already exists, \
and cannot automatically be repaired.",
						file_bk_path.display()
					);
					return Err("sessions corrupt".into());
				}

				let session = block_on(
					context
						.session_store
						.load_session(&address, context.get_signal_ctx().get()),
				)?;

				match session {
					Some(s) => {
						// If there is no current session, do not bother saving it.
						//if !s.has_current_session_state() {
						//	continue;
						//} else {

						let bytes = s.serialize()?;
						let mut file = OpenOptions::new()
							.truncate(true)
							.write(true)
							.create(true)
							.open(&file_bk_path)?;
						{
							let mut buf = BufWriter::new(&mut file);
							buf.write_all(bytes.as_slice())?;
							buf.flush()?;
						}
						file.sync_all()?;
						fs::rename(file_bk_path, file_path)?;
						//}
					}
					None => {
						//todo: Better error handling here.
						continue;
					}
				}
			} else {
				warn!(
					"No UUID for {:?}, cannot write sessions.",
					&peer_record.number
				);
			}
		}
		info!(
			"End of auxin_cli's save_peer_sessions() at {}",
			generate_timestamp()
		);
		Ok(())
	}

	fn save_all_peer_records(&mut self, context: &AuxinContext) -> crate::Result<()> {
		info!(
			"Start of auxin_cli's save_all_peer_records() at {}",
			generate_timestamp()
		);
		let our_path = self.get_protocol_store_path(context);

		let recipients_path = our_path.join("recipients-store");

		// Working copy
		let recipients_bk_path = recipients_path.with_extension("bk");

		if recipients_bk_path.exists() {
			error!(
				"Working copy of recipients-store {} already exists, \
and cannot automatically be repaired.",
				recipients_bk_path.display()
			);
			return Err("recipients-store corrupt".into());
		}

		// Save recipient store:
		let mut bk_file = OpenOptions::new()
			.truncate(true)
			.write(true)
			.create(true)
			.open(&recipients_bk_path)?;
		{
			let mut buf = BufWriter::new(&mut bk_file);
			serde_json::to_writer_pretty(&mut buf, &context.peer_cache)?;
			buf.flush()?;
		}
		bk_file.sync_all()?;
		fs::rename(recipients_bk_path, recipients_path)?;

		let identities_path = our_path.join("identities");
		for recip in context.peer_cache.peers.iter() {
			if let Some(ident) = &recip.identity {
				let id = recip.id;
				let file_path = identities_path.join(id.to_string());
				let file_bk_path = file_path.with_extension("bk");
				if file_bk_path.exists() {
					error!(
						"Working copy of peer identity {} already exists, \
and cannot automatically be repaired.",
						file_bk_path.display()
					);
					return Err("peer corrupt".into());
				}
				let mut file = OpenOptions::new()
					.truncate(true)
					.write(true)
					.create(true)
					.open(&file_bk_path)?;
				{
					let mut buf = BufWriter::new(&mut file);
					serde_json::to_writer_pretty(&mut buf, ident)?;
					buf.flush()?;
				}
				file.sync_all()?;
				fs::rename(file_bk_path, file_path)?;
			}
		}

		info!(
			"End of auxin_cli's save_all_peer_records() at {}",
			generate_timestamp()
		);
		Ok(())
	}

	/// Saves all peer records, as there currently is not a way to save just one.
	fn save_peer_record(
		&mut self,
		_peer: &AuxinAddress,
		context: &AuxinContext,
	) -> crate::Result<()> {
		// Unfortunately I do not see a way to save a single user without saving all users in
		// a libsignal-cli style json protocol store.
		self.save_all_peer_records(context)
	}

	/// Currently no-ops
	fn save_pre_keys(&mut self, _context: &AuxinContext) -> crate::Result<()> {
		// TODO: Currently there is no circumstance where Auxin mutates pre-keys,
		// so I do not know the specifics of what is necessary.
		Ok(())
	}

	/// Currently no-ops
	fn save_our_identity(&mut self, _context: &AuxinContext) -> crate::Result<()> {
		// TODO: Currently there is no circumstance where Auxin mutates our own identity,
		// so I do not know the specifics of what is necessary.
		// Most likely this will be relevant if we need to generate a new profile key.
		Ok(())
	}

	/// This does nothing for signal-cli, since we flush immediately.
	fn flush(&mut self, _context: &AuxinContext) -> crate::Result<()> {
		Ok(())
	}

	fn end_session(&mut self, _peer: &AuxinAddress, _context: &AuxinContext) -> auxin::Result<()> {
		/*
		// DELETING FILES MAY BE COUNTERPRODUCTIVE, pending further testing.


		let our_path = self.get_protocol_store_path(context);
		let mut session_path = our_path.clone();
		session_path.push_str("sessions/");

		if !Path::new(&session_path).exists() {
			std::fs::create_dir(&session_path)?;
		}

		// Pull up the relevant peer
		let peer_record = match context.peer_cache.get(peer) {
			Some(a) => a,
			// We do not need to save what is not there.
			None => {
				return Ok(());
			}
		};

		for device_id in peer_record.device_ids_used.iter() {
			let device_session_path = format!("{}{}_{}", &session_path, &peer_record.id, &device_id);
			if Path::new(&device_session_path).exists() {
				std::fs::remove_file(&device_session_path)?;
			}
		} */
		Ok(())
	}

	fn load_group_protobuf(&mut self, context: &AuxinContext, group_id: &auxin::groups::GroupId) -> auxin::Result<auxin_protos::DecryptedGroup> {
        let group_file_name = group_id.to_base64();
		let group_file_path = self.get_protocol_store_path(&context).join("group-cache").join(&group_file_name);

		let file = File::open(&group_file_path)?;
		let mut buf_reader = BufReader::new(file);
		let mut file_stream = CodedInputStream::from_buffered_reader(&mut buf_reader);
		// Deserialize an auxin_protos::DecryptedGroup
		Ok( file_stream.read_message()? )
    }

	fn load_group_info(&mut self, context: &AuxinContext, group_id: &auxin::groups::GroupId) -> auxin::Result<auxin::groups::group_storage::GroupInfoStorage> {
		todo!()
	}

	fn save_group_info(&mut self, context: &AuxinContext, group_id: &auxin::groups::GroupId, group_info: auxin::groups::group_storage::GroupInfoStorage) -> auxin::Result<()> {
		todo!()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use terminator::Terminator;

	type Result<T> = std::result::Result<T, Terminator>;

	/// Test this module can parse a signal-cli json file.
	///
	/// This naturally requires that one is symlinked to `state`
	/// in the root of the repository.
	///
	/// This picks an unspecified file to try and deserialize.
	#[test]
	#[ignore = "requires real config"]
	fn test_config_parse() -> Result<()> {
		let path = Path::new("../state/data");
		// Ensure we actually parse *something* and the directory isnt just empty/missing files
		// If anything fails to parse it'll error, failing the test.
		let mut done = false;
		let mut state = StateManager::new_test(path.to_path_buf());
		for file in fs::read_dir(path)? {
			let file = file?;
			let name = file.file_name().to_str().unwrap().to_string();
			if name.ends_with('d') {
				continue;
			}
			let _local_identity = state.load_local_identity(&name)?;
			done = true
		}
		assert!(done, "state is empty, didn't actually parse anything");
		Ok(())
	}
}
