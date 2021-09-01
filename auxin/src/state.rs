use core::fmt;
use std::{cmp::Ordering, collections::HashMap};

use libsignal_protocol::{IdentityKey, PreKeyBundle, PublicKey};
use log::warn;
use serde::{
	de::{self, Visitor},
	Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{
	address::{AuxinAddress, AuxinDeviceAddress, E164},
	generate_timestamp, AuxinConfig, AuxinContext, LocalIdentity,
};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UnidentifiedAccessMode {
	ENABLED,
	DISABLED,
	UNRESTRICTED,
}

impl Serialize for UnidentifiedAccessMode {
	fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match &self {
			UnidentifiedAccessMode::ENABLED => serializer.serialize_str("ENABLED"),
			UnidentifiedAccessMode::DISABLED => serializer.serialize_str("DISABLED"),
			UnidentifiedAccessMode::UNRESTRICTED => serializer.serialize_str("UNRESTRICTED"),
		}
	}
}

impl<'de> Deserialize<'de> for UnidentifiedAccessMode {
	fn deserialize<D>(deserializer: D) -> std::result::Result<UnidentifiedAccessMode, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct UnidentifiedAccessModeVisitor;

		impl<'de> Visitor<'de> for UnidentifiedAccessModeVisitor {
			type Value = UnidentifiedAccessMode;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("'ENABLED', 'DISABLED', or any regular boolean type")
			}
			fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
				match value {
					true => Ok(UnidentifiedAccessMode::ENABLED),
					false => Ok(UnidentifiedAccessMode::DISABLED),
				}
			}
			fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
				let upper_string = value.to_ascii_uppercase();
				if upper_string.eq_ignore_ascii_case("ENABLED")
					|| upper_string.eq_ignore_ascii_case("\"ENABLED\"")
				{
					Ok(UnidentifiedAccessMode::ENABLED)
				} else if upper_string.eq_ignore_ascii_case("DISABLED")
					|| upper_string.eq_ignore_ascii_case("\"DISABLED\"")
				{
					Ok(UnidentifiedAccessMode::DISABLED)
				} else if upper_string.eq_ignore_ascii_case("UNRESTRICTED")
					|| upper_string.eq_ignore_ascii_case("\"UNRESTRICTED\"")
				{
					Ok(UnidentifiedAccessMode::UNRESTRICTED)
				} else {
					warn!("Invalid \"unidentifiedAccessMode\" string. Should be ENABLED, DISABLED, or UNRESTRICTED - we received {}. Evaluating as DISABLED.", value);
					Ok(UnidentifiedAccessMode::DISABLED)
				}
			}
		}
		deserializer.deserialize_any(UnidentifiedAccessModeVisitor)
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PeerProfile {
	pub last_update_timestamp: u64,
	pub given_name: Option<String>,
	pub family_name: Option<String>,
	pub about: Option<String>,
	pub about_emoji: Option<String>,
	pub unidentified_access_mode: UnidentifiedAccessMode,
	pub capabilities: Vec<String>,
}

/// A peer profile as it comes in from https://textsecure-service.whispersystems.org/v1/profile/[UUID]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForeignPeerProfile {
	pub identity_key: String,
	pub name: String,
	pub about: Option<String>,
	pub about_emoji: Option<String>,
	pub avatar: Option<String>,
	pub payment_address: Option<String>,
	pub unidentified_access: Option<String>,
	pub unrestricted_unidentified_access: bool,
	pub capabilities: HashMap<String, bool>,
	pub username: Option<String>,
	pub uuid: Option<String>,
	pub credential: Option<String>,
}

impl ForeignPeerProfile {
	pub fn to_local(&self) -> PeerProfile {
		let unidentified_access_mode = match (
			self.unrestricted_unidentified_access,
			self.unidentified_access.is_some(),
		) {
			(true, _) => UnidentifiedAccessMode::UNRESTRICTED,
			(false, true) => UnidentifiedAccessMode::ENABLED,
			(false, false) => UnidentifiedAccessMode::DISABLED,
		};

		let mut capabilities: Vec<String> = Vec::default();
		for (cap, enabled) in self.capabilities.iter() {
			if *enabled {
				capabilities.push(cap.clone());
			}
		}

		// Difference between username and name?
		PeerProfile {
			last_update_timestamp: generate_timestamp(),
			given_name: None,
			family_name: None,
			about: self.about.clone(),
			about_emoji: self.about_emoji.clone(),
			unidentified_access_mode,
			capabilities,
		}
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PeerRecord {
	pub id: u64,
	pub number: String,
	pub uuid: Option<uuid::Uuid>,
	pub profile_key: Option<String>,
	pub profile_key_credential: Option<String>,
	pub contact: Option<Value>, //TODO
	pub profile: Option<PeerProfile>,
	#[serde(skip)]
	pub device_ids_used: Vec<u32>,
	#[serde(skip)]
	pub identity: Option<PeerIdentity>,
}

impl PeerRecord {
	pub fn supports_sealed_sender(&self) -> bool {
		match &self.profile {
			Some(profile) => {
				self.profile_key.is_some()
					&& (profile.unidentified_access_mode != UnidentifiedAccessMode::DISABLED)
			}
			None => false,
		}
	}
}

impl Ord for PeerRecord {
	fn cmp(&self, other: &Self) -> Ordering {
		self.id.cmp(&other.id)
	}
}

impl PartialOrd for PeerRecord {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl PartialEq for PeerRecord {
	fn eq(&self, other: &Self) -> bool {
		self.id == other.id
			&& self.number.eq_ignore_ascii_case(other.number.as_str())
			&& self.uuid == other.uuid
	}
}

impl Eq for PeerRecord {}

impl From<&PeerRecord> for AuxinAddress {
	fn from(val: &PeerRecord) -> Self {
		if let Some(uuid) = &val.uuid {
			AuxinAddress::Both(val.number.clone(), uuid.clone())
		} else {
			AuxinAddress::Phone(val.number.clone())
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PeerRecordStructure {
	#[serde(rename = "recipients")]
	pub peers: Vec<PeerRecord>,
	#[serde(rename = "lastId")]
	pub last_id: u64,
}

// Many helper functions.
pub trait PeerStore {
	fn get_by_number(&self, phone_number: &E164) -> Option<&PeerRecord>;
	fn get_by_uuid(&self, peer_uuid: &Uuid) -> Option<&PeerRecord>;
	fn get_by_number_mut(&mut self, phone_number: &E164) -> Option<&mut PeerRecord>;
	fn get_by_uuid_mut(&mut self, peer_uuid: &Uuid) -> Option<&mut PeerRecord>;
	fn push(&mut self, peer: PeerRecord);
	fn get(&self, address: &AuxinAddress) -> Option<&PeerRecord>;
	fn get_mut(&mut self, address: &AuxinAddress) -> Option<&mut PeerRecord>;

	fn complete_phone_address(&self, phone_number: &String) -> Option<AuxinAddress> {
		self.get_by_number(phone_number)
			.map(|peer| AuxinAddress::from(peer))
	}
	fn complete_uuid_address(&self, peer_uuid: &Uuid) -> Option<AuxinAddress> {
		self.get_by_uuid(peer_uuid)
			.map(|peer| AuxinAddress::from(peer))
	}
	/// If we only have a phone number or a UUID, fill in the other one,. Returns None if no peer by this address is found.
	fn complete_address(&self, address: &AuxinAddress) -> Option<AuxinAddress> {
		if let AuxinAddress::Both(_, _) = address {
			return Some(address.clone());
		} else {
			return (address
				.get_phone_number()
				.ok()
				.map(|p| self.complete_phone_address(p))
				.or(address
					.get_uuid()
					.ok()
					.map(|u| self.complete_uuid_address(u))))
			.flatten();
		}
	}
	/// Returns a list of Auxin Device Addresses, one for each known device ID used by the peer referred to with 'address'.
	/// Returns None if no peer by this address is found.
	fn get_device_addresses(&self, address: &AuxinAddress) -> Option<Vec<AuxinDeviceAddress>> {
		self.get(address)
			.map(|peer| {
				peer.device_ids_used
					.iter()
					.map(|i| AuxinDeviceAddress {
						address: address.clone(),
						device_id: *i,
					})
					.collect()
				// Empty lists of device IDs should return None.
			})
			.filter(|v: &Vec<AuxinDeviceAddress>| !v.is_empty())
	}
}

// Many helper functions.

impl PeerStore for PeerRecordStructure {
	fn get_by_number(&self, phone_number: &E164) -> Option<&PeerRecord> {
		self.peers
			.iter()
			.find(|i| i.number.eq_ignore_ascii_case(phone_number))
	}
	fn get_by_uuid(&self, peer_uuid: &Uuid) -> Option<&PeerRecord> {
		self.peers.iter().find(|i| {
			if i.uuid.is_some() {
				i.uuid.unwrap() == *peer_uuid
			} else {
				false
			}
		})
	}
	fn get_by_number_mut(&mut self, phone_number: &E164) -> Option<&mut PeerRecord> {
		self.peers
			.iter_mut()
			.find(|i| i.number.eq_ignore_ascii_case(phone_number))
	}
	fn get_by_uuid_mut(&mut self, peer_uuid: &Uuid) -> Option<&mut PeerRecord> {
		self.peers.iter_mut().find(|i| {
			if i.uuid.is_some() {
				i.uuid.unwrap() == *peer_uuid
			} else {
				false
			}
		})
	}
	fn push(&mut self, peer: PeerRecord) {
		let id = peer.id;
		self.peers.push(peer);
		if id > self.last_id {
			self.last_id = id;
		}
	}

	fn get(&self, address: &AuxinAddress) -> Option<&PeerRecord> {
		let address = self.complete_address(address);
		match address {
			Some(AuxinAddress::Phone(phone_number)) => self.get_by_number(&phone_number),
			Some(AuxinAddress::Uuid(peer_uuid)) => self.get_by_uuid(&peer_uuid),
			Some(AuxinAddress::Both(phone_number, peer_uuid)) => self
				.get_by_number(&phone_number)
				.or(self.get_by_uuid(&peer_uuid)),
			None => None,
		}
	}
	fn get_mut(&mut self, address: &AuxinAddress) -> Option<&mut PeerRecord> {
		let address = self.complete_address(address);
		match address {
			Some(AuxinAddress::Phone(phone_number)) => self.get_by_number_mut(&phone_number),
			Some(AuxinAddress::Uuid(peer_uuid)) => self.get_by_uuid_mut(&peer_uuid),
			Some(AuxinAddress::Both(phone_number, peer_uuid)) => self.peers.iter_mut().find(|i| {
				i.number.eq_ignore_ascii_case(&phone_number) || {
					if i.uuid.is_some() {
						i.uuid.unwrap() == peer_uuid
					} else {
						false
					}
				}
			}),
			None => None,
		}
	}
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct PeerIdentity {
	pub identity_key: String,
	pub trust_level: Option<i32>,
	pub added_timestamp: Option<u64>,
}

/// Represents a foreign Pre Key that the server has sent us.
/// This is equivalent to a libsignal_protocol::state::PreKeyRecord!
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyReply {
	pub key_id: u32,
	/// Public key stored as Base64
	pub public_key: String,
}

/// Represents a foreign Signed Pre Key that the server has sent us.
/// This is equivalent to a libsignal_protocol::state::SignedPreKeyRecord!
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreKeyReply {
	pub key_id: u32,
	/// Public key stored as Base64
	pub public_key: String,
	/// Signature as base-64
	pub signature: String,
}

/// Info on a particular peer's device as sent to us in a reply to GET https://textsecure-service.whispersystems.org/v2/keys/[UUID]/
/// This is equivalent to a libsignal_protocol::state::PreKeyBundle!
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PeerDeviceInfo {
	pub device_id: u32,
	pub registration_id: u32,
	pub signed_pre_key: SignedPreKeyReply,
	pub pre_key: Option<PreKeyReply>,
}

impl PeerDeviceInfo {
	pub fn convert_to_pre_key_bundle(
		&self,
		identity_key: &IdentityKey,
	) -> crate::Result<PreKeyBundle> {
		let pre_key = match &self.pre_key {
			Some(reply) => {
				let public_key = base64::decode(&reply.public_key)?;
				Some((reply.key_id, PublicKey::deserialize(public_key.as_slice())?))
			}
			None => None,
		};

		let signed_pre_key_bytes = base64::decode(&self.signed_pre_key.public_key)?;
		let signed_pre_key_public = PublicKey::deserialize(&signed_pre_key_bytes)?;

		let signed_pre_key_signature = base64::decode(&self.signed_pre_key.signature)?;

		Ok(PreKeyBundle::new(
			self.registration_id,
			self.device_id,
			pre_key,
			self.signed_pre_key.key_id,
			signed_pre_key_public,
			signed_pre_key_signature,
			identity_key.clone(),
		)?)
	}
}

/// Info on a particular peer as sent to us in a reply to GET https://textsecure-service.whispersystems.org/v2/keys/[UUID]/
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfoReply {
	/// Identity key encoded as Base64
	pub identity_key: String,
	pub devices: Vec<PeerDeviceInfo>,
}

impl PeerInfoReply {
	pub fn convert_to_pre_key_bundles(self) -> crate::Result<Vec<(u32, PreKeyBundle)>> {
		let id_key_bytes = base64::decode(&self.identity_key)?;
		let id_key = IdentityKey::decode(&id_key_bytes)?;
		let mut out_vec: Vec<(u32, PreKeyBundle)> = Vec::default();
		for device in self.devices.iter() {
			out_vec.push((device.device_id, device.convert_to_pre_key_bundle(&id_key)?));
		}
		return Ok(out_vec);
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfileCapabilitiesResponse {
	pub gv2: bool,
	#[serde(rename = "senderKey")]
	pub sender_key: bool,
	#[serde(rename = "announcementGroup")]
	pub announcement_group: bool,
	#[serde(rename = "gv1-migration")]
	pub gv1_migration: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProfileResponse {
	/// Base-64
	pub identity_key: String,
	/// Base-64
	pub name: Option<String>,
	/// Base-64
	pub about: Option<String>,
	/// Base-64
	pub about_emoji: Option<String>,
	/// Follows the form of "profiles/{Base-64 string}
	pub avatar: Option<String>,
	/// Base-64 encoded signalservice.proto:PaymentAddress
	pub payment_address: Option<String>,
	/// Base-64
	pub unidentified_access: Option<String>,
	pub unrestricted_unidentified_access: bool,
	pub capabilities: ProfileCapabilitiesResponse,
	/// As of yet unused, at least as far as I can see.
	pub username: Option<String>,
	pub uuid: Option<Uuid>,
	/// "Credential key," base-64 encoded.
	pub credential: Option<String>,
}

pub trait AuxinStateManager {
	fn load_local_identity(&mut self, phone_number: &E164) -> crate::Result<LocalIdentity>;
	fn load_context(
		&mut self,
		credentials: &LocalIdentity,
		config: AuxinConfig,
	) -> crate::Result<AuxinContext>;
	/// Save the entire InMemSessionStore from this AuxinContext to wherever state is held
	fn save_all_sessions(&mut self, context: &AuxinContext) -> crate::Result<()> {
		for peer in context.peer_cache.peers.iter() {
			let address = AuxinAddress::Phone(peer.number.clone());
			self.save_peer_sessions(&address, &context)?;
		}
		Ok(())
	}
	/// Save the sessions (may save multiple sessions - one per each of the peer's devices) from a specific peer
	fn save_peer_sessions(
		&mut self,
		peer: &AuxinAddress,
		context: &AuxinContext,
	) -> crate::Result<()>;
	/// Save peer record info from all peers.
	fn save_all_peer_records(&mut self, context: &AuxinContext) -> crate::Result<()>;
	/// Save peer record info from a specific peer.
	fn save_peer_record(
		&mut self,
		peer: &AuxinAddress,
		context: &AuxinContext,
	) -> crate::Result<()>;
	/// Saves both pre_key_store AND signed_pre_key_store from the context.
	fn save_pre_keys(&mut self, context: &AuxinContext) -> crate::Result<()>;
	/// Saves our identity - this is unlikely to change often, but sometimes we may need to change things like, for example, our profile key.
	fn save_our_identity(&mut self, context: &AuxinContext) -> crate::Result<()>;
	/// Ensure all changes are fully saved, not just queued. Awaiting on this should block for as long as is required to ensure no data loss.
	fn flush(&mut self, context: &AuxinContext) -> crate::Result<()>;
	/// Saves absolutely every relevant scrap of data we have loaded
	fn save_entire_context(&mut self, context: &AuxinContext) -> crate::Result<()> {
		self.save_our_identity(&context)?;
		self.save_all_peer_records(&context)?;
		self.save_pre_keys(&context)?;
		self.save_all_sessions(&context)?;
		self.flush(&context)?;
		Ok(())
	}
}
