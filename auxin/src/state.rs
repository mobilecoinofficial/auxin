use core::fmt;
use std::cmp::Ordering;

//use libsignal_protocol::{Context, IdentityKey, IdentityKeyStore, InMemIdentityKeyStore, InMemPreKeyStore, InMemSessionStore, InMemSignedPreKeyStore, PreKeyRecord, PreKeyStore, ProtocolAddress, SessionRecord, SessionStore, SignedPreKeyRecord, SignedPreKeyStore};
use log::{debug};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::{self, Visitor}};
use serde_json::Value;
use uuid::Uuid;
use async_trait::async_trait;

use crate::{AuxinContext, LocalIdentity, address::{AuxinAddress, AuxinDeviceAddress, E164}};

#[derive(Debug, Copy, Clone)]
pub enum UnidentifiedAccessMode {
	ENABLED, 
	DISABLED, 
	UNRESTRICTED
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
				}else if upper_string.eq_ignore_ascii_case("UNRESTRICTED")
					|| upper_string.eq_ignore_ascii_case("\"UNRESTRICTED\"")
				{
					Ok(UnidentifiedAccessMode::UNRESTRICTED)
				} else {
					debug!("Invalid \"unidentifiedAccessMode\" string. Should be ENABLED, DISABLED, or UNRESTRICTED - we received {}", value);
					//TODO: Error rather than silently evaluate non-"ENABLED" members to false.
					Ok(UnidentifiedAccessMode::DISABLED)
				}
			}
		}
		deserializer.deserialize_any(UnidentifiedAccessModeVisitor)
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")] //It's that easy. Serde is magic. God-tier.
pub struct PeerProfile {
	pub last_update_timestamp: u64,
	pub given_name: Option<String>,
	pub family_name: Option<String>,
	pub about: Option<String>,
	pub about_emoji: Option<String>,
	pub unidentified_access_mode: UnidentifiedAccessMode,
	pub capabilities: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PeerRecord {
	pub id: u64,
	pub number: String,
	pub uuid: uuid::Uuid,
	pub profile_key: Option<String>,
	pub profile_key_credential: Option<String>,
	pub contact: Option<Value>, //TODO
	pub profile: Option<PeerProfile>,
	#[serde(skip)]
	pub device_ids_used: Vec<u32>,
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
        AuxinAddress::Both(val.number.clone(), val.uuid.clone())
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
        self.get_by_number(phone_number).map(|peer| AuxinAddress::from(peer))
    }
    fn complete_uuid_address(&self, peer_uuid: &Uuid) -> Option<AuxinAddress> {
        self.get_by_uuid(peer_uuid).map(|peer| AuxinAddress::from(peer))
    }
    /// If we only have a phone number or a UUID, fill in the other one,. Returns None if no peer by this address is found.
    fn complete_address(&self, address: &AuxinAddress) -> Option<AuxinAddress> {
        if let AuxinAddress::Both(_, _) = address {
            return Some(address.clone());
        }
        else {
            return (address.get_phone_number().ok().map(|p| self.complete_phone_address(p))
            .or(address.get_uuid().ok().map(|u| self.complete_uuid_address(u)))
            ).flatten();
        }
    }
    /// Returns a list of Auxin Device Addresses, one for each known device ID used by the peer referred to with 'address'. 
    /// Returns None if no peer by this address is found.
    fn get_device_addresses(&self, address: &AuxinAddress) -> Option<Vec<AuxinDeviceAddress>> {
        self.get(address).map(|peer | {
            peer.device_ids_used.iter().map(|i | {
                AuxinDeviceAddress {
                    address: address.clone(),
                    device_id: *i,
                }
            }).collect()
            // Empty lists of device IDs should return None.
        }).filter(|v: &Vec<AuxinDeviceAddress>| !v.is_empty())
    }
}

// Many helper functions.

impl PeerStore for PeerRecordStructure {
	fn get_by_number(&self, phone_number: &E164) -> Option<&PeerRecord> {
		self.peers.iter().find(|i | i.number.eq_ignore_ascii_case(phone_number) )
	}
	fn get_by_uuid(&self, peer_uuid: &Uuid) -> Option<&PeerRecord> {
		self.peers.iter().find(|i | i.uuid == *peer_uuid )
	}
	fn get_by_number_mut(&mut self, phone_number: &E164) -> Option<&mut PeerRecord> {
		self.peers.iter_mut().find(|i | i.number.eq_ignore_ascii_case(phone_number) )
	}
	fn get_by_uuid_mut(&mut self, peer_uuid: &Uuid) -> Option<&mut PeerRecord> {
		self.peers.iter_mut().find(|i | i.uuid == *peer_uuid )
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
            Some(AuxinAddress::Phone(phone_number)) => { 
                self.get_by_number(&phone_number)
            },
            Some(AuxinAddress::Uuid(peer_uuid)) => { 
                self.get_by_uuid(&peer_uuid)
            },
            Some(AuxinAddress::Both(phone_number, peer_uuid)) => { 
                self.get_by_number(&phone_number).or(self.get_by_uuid(&peer_uuid))
            },
            None => None,
        }
	}
    fn get_mut(&mut self, address: &AuxinAddress) -> Option<&mut PeerRecord> {
        let address = self.complete_address(address);
		match address {
            Some(AuxinAddress::Phone(phone_number)) => {
                self.get_by_number_mut(&phone_number)
            },
            Some(AuxinAddress::Uuid(peer_uuid)) => {
                self.get_by_uuid_mut(&peer_uuid)
            },
            Some(AuxinAddress::Both(phone_number, peer_uuid)) => {
                self.peers.iter_mut().find(|i | (i.number.eq_ignore_ascii_case(&phone_number) || (i.uuid == peer_uuid) ))
            },
            None => None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PeerIdentity {
	pub identity_key : String,
	pub trust_level : Option<i32>,
	pub added_timestamp : Option<u64>,
}

#[async_trait]
pub trait AuxinStateManager {
	async fn load_local_identity(&mut self, phone_number: &E164) -> crate::Result<LocalIdentity>;
	async fn load_context(&mut self, credentials: &LocalIdentity) -> crate::Result<AuxinContext>;
	/// Save the entire InMemSessionStore from this AuxinContext to wherever state is held
	async fn save_all_sessions(&mut self, context: &AuxinContext) -> std::result::Result<(), Box<dyn std::error::Error + Send>> {
		for peer in context.peer_cache.peers.iter() {
			let address = AuxinAddress::Phone(peer.number.clone());
			self.save_peer_sessions(&address, &context).await?;
		}
		Ok(())
	}
	/// Save the sessions (may save multiple sessions - one per each of the peer's devices) from a specific peer 
	async fn save_peer_sessions(&mut self, peer: &AuxinAddress, context: &AuxinContext) -> std::result::Result<(), Box<dyn std::error::Error + Send>> ;
	/// Save peer record info from all peers.
	async fn save_all_peer_records(&mut self, context: &AuxinContext) ->  std::result::Result<(), Box<dyn std::error::Error + Send>>  ;
	/// Save peer record info from a specific peer.
	async fn save_peer_record(&mut self, peer: &AuxinAddress, context: &AuxinContext) ->  std::result::Result<(), Box<dyn std::error::Error + Send>>  ;
	/// Saves both pre_key_store AND signed_pre_key_store from the context. 
	async fn save_pre_keys(&mut self, context: &AuxinContext) ->  std::result::Result<(), Box<dyn std::error::Error + Send>>  ;
	/// Saves our identity - this is unlikely to change often, but sometimes we may need to change things like, for example, our profile key.
	async fn save_our_identity(&mut self, context: &AuxinContext) ->  std::result::Result<(), Box<dyn std::error::Error + Send>>  ;
	/// Ensure all changes are fully saved, not just queued. Awaiting on this should block for as long as is required to ensure no data loss. 
	async fn flush(&mut self, context: &AuxinContext) ->  std::result::Result<(), Box<dyn std::error::Error + Send>>  ;
	/// Saves absolutely every relevant scrap of data we have loaded
	async fn save_entire_context(&mut self, context: &AuxinContext) ->  std::result::Result<(), Box<dyn std::error::Error + Send>> { 
		self.save_our_identity(&context).await?;
		self.save_all_peer_records(&context).await?;
		self.save_pre_keys(&context).await?;
		self.save_all_sessions(&context).await?;
		self.flush(&context).await?;
		Ok(())
	}

	/// Saves and finalizes all data - must be a blocking operation.
	fn save_on_quit(&mut self, context: &AuxinContext) -> crate::Result<()>;
}