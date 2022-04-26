// Copyright (c) 2022 MobileCoin Inc.
// Copyright (c) 2022 Emily Cultip

use auxin_protos::groups::member::Role as MemberRole;
use auxin_protos::storage::SenderKeyRecordStructure;
use log::debug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zkgroup::{profiles::ProfileKey, GROUP_MASTER_KEY_LEN, PROFILE_KEY_LEN};

use crate::{
	utils::{serde_base64, serde_optional_base64},
	Timestamp, generate_timestamp, state::{PeerStore, PeerRecordStructure},
};

use super::{GroupMemberInfo, sender_key::DistributionId};

#[derive(Debug, thiserror::Error)]
pub enum GroupSerializationError {
	#[error(
		"could not deserialize group master key - master keys are 32 bytes and this one was {0}"
	)]
	WrongMasterKeyLength(usize),
	#[error("could not deserialize profile key - profile keys are 32 bytes and this one was {0}")]
	WrongProfileKeyLength(usize),
	#[error(
		"member role given was {0}. Valid roles are \"UNKNOWN\", \"DEFAULT\", or \"ADMINISTRATOR\""
	)]
	NotARole(String),
	#[error("Failed to decode base-64 for group storage: {0}.")]
	Base64Decode(#[from] base64::DecodeError),
}

/// Holds per-member information about the last time we sent a peer a distribution message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct LocalDistributionRecord { 
	pub distribution_id: DistributionId,
	pub distribution_time: Timestamp,
	/// Which of this peer's devices have we sent this to?
	pub devices_included: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct GroupMemberStorage {
	pub id: Uuid,
	#[serde(with = "serde_optional_base64")]
	pub profile_key: Option<Vec<u8>>,
	pub member_role: String,
	pub joined_at_revision: u32,
	pub last_distribution: Option<LocalDistributionRecord>,
}

impl TryFrom<GroupMemberStorage> for GroupMemberInfo {
	type Error = GroupSerializationError;

	fn try_from(value: GroupMemberStorage) -> Result<Self, Self::Error> {
		let profile_key = if let Some(pk) = value.profile_key {
			if pk.len() == PROFILE_KEY_LEN {
				let mut bytes: [u8; PROFILE_KEY_LEN] = [0; PROFILE_KEY_LEN];
				bytes.copy_from_slice(&pk[0..PROFILE_KEY_LEN]);
				Some(ProfileKey::create(bytes))
			} else {
				return Err(GroupSerializationError::WrongProfileKeyLength(pk.len()));
			}
		} else {
			None
		};
		let role = match value.member_role.to_ascii_uppercase().as_str() {
			"UNKNOWN" => MemberRole::UNKNOWN,
			"DEFAULT" => MemberRole::DEFAULT,
			"ADMINISTRATOR" => MemberRole::ADMINISTRATOR,
			not_role => {
				return Err(GroupSerializationError::NotARole(not_role.to_string()));
			}
		};
		Ok(Self {
			id: value.id,
			profile_key,
			member_role: role,
			joined_at_revision: value.joined_at_revision,
			last_distribution: value.last_distribution,
		})
	}
}

impl From<GroupMemberInfo> for GroupMemberStorage {
	fn from(value: GroupMemberInfo) -> Self {
		GroupMemberStorage {
			id: value.id,
			profile_key: value.profile_key.map(|pk| pk.bytes.to_vec()),
			member_role: match value.member_role {
				MemberRole::UNKNOWN => "UNKNOWN",
				MemberRole::DEFAULT => "DEFAULT",
				MemberRole::ADMINISTRATOR => "ADMINISTRATOR",
			}
			.to_string(),
			joined_at_revision: value.joined_at_revision,
			last_distribution: value.last_distribution,
		}
	}
}

#[derive(Clone, Debug)]
pub struct GroupInfo {
	pub revision: u32,
	pub master_key: [u8; GROUP_MASTER_KEY_LEN],
	pub members: Vec<GroupMemberInfo>,
	pub local_distribution_id: Option<Uuid>,
	pub last_distribution_timestamp: Timestamp,
}

impl GroupInfo { 
	/// Do we need to generate a sender-key distribution message to send sender-key messages to this group? 
	pub fn needs_new_distribution(&self, distribution_lifespan: u64) -> bool { 
		let now = generate_timestamp(); 
		//Has the group-global one expired?
		if (now - self.last_distribution_timestamp) > distribution_lifespan { 
			return true;
		} else if self.local_distribution_id.is_none() { 
			return true;
		}

		for member in self.members.iter() { 
			if let Some(distrib) = member.last_distribution.as_ref() { 
				// Check for expiration.
				if (now - distrib.distribution_time) > distribution_lifespan { 
					debug!("A sender key distribution ID has expired. Regenerating..."); 
					return true;
				}
			}
			else { 
				//We haven't sent one, make a new distribution.
				return true;
			}
		}
		false
	}
	/// Used to record a sender key distribution message sent to every group member.
	pub fn set_distribution_all(&mut self, distribution_id: &DistributionId, distribution_timestamp: Timestamp, peers: &PeerRecordStructure){
		self.local_distribution_id = Some(distribution_id.clone());
		self.last_distribution_timestamp = distribution_timestamp;
		for member in self.members.iter_mut() { 
			let member_uuid = member.id.clone();
			member.last_distribution = Some( 
				LocalDistributionRecord {
					distribution_id: distribution_id.clone(),
					distribution_time: distribution_timestamp,
					devices_included: peers.get_by_uuid(&member_uuid).unwrap().device_ids_used.iter().cloned().collect(),
				}
			);
		}
	}
}

impl PartialOrd for GroupInfo {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		self.master_key.partial_cmp(&other.master_key)
	}
}
impl std::hash::Hash for GroupInfo {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		self.master_key.hash(state);
	}
}
impl PartialEq for GroupInfo {
	fn eq(&self, other: &Self) -> bool {
		self.master_key == other.master_key
	}
}
impl Eq for GroupInfo {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInfoStorage {
	revision: u32,
	/// Group master key. Length will be validated to ensure this is a [u8; zkgroup::GROUP_MASTER_KEY_LEN]
	#[serde(with = "serde_base64")]
	master_key: Vec<u8>,
	members: Vec<GroupMemberStorage>,
	pub local_distribution_id: Option<Uuid>,
	pub last_distribution_timestamp: Option<Timestamp>,
}
impl TryFrom<GroupInfoStorage> for GroupInfo {
	type Error = GroupSerializationError;

	fn try_from(value: GroupInfoStorage) -> Result<Self, Self::Error> {
		let master_key = if value.master_key.len() == GROUP_MASTER_KEY_LEN {
			let mut bytes: [u8; GROUP_MASTER_KEY_LEN] = [0; GROUP_MASTER_KEY_LEN];
			bytes.copy_from_slice(&value.master_key[0..GROUP_MASTER_KEY_LEN]);
			bytes
		} else {
			return Err(GroupSerializationError::WrongMasterKeyLength(
				value.master_key.len(),
			));
		};
		let mut members = Vec::new();
		for member in value.members.iter() {
			members.push(member.clone().try_into()?);
		}

		Ok(GroupInfo {
			revision: value.revision,
			master_key,
			members,
			local_distribution_id: value.local_distribution_id,
			last_distribution_timestamp: value.last_distribution_timestamp.or(Some(0)).unwrap(),
		})
	}
}

impl From<&GroupInfo> for GroupInfoStorage {
	fn from(value: &GroupInfo) -> Self {
		let mut members = Vec::new();
		for member in value.members.iter() {
			members.push(member.clone().into());
		}

		GroupInfoStorage {
			revision: value.revision,
			master_key: value.master_key.to_vec(),
			members,
			local_distribution_id: value.local_distribution_id,
			last_distribution_timestamp: Some(value.last_distribution_timestamp),
		}
	}
}

/// Used to keep track of which sender keys this Signal node has *sent*,
/// i.e. device ID is implicit and there's no "peer ID"
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSenderKeyRecord {
	pub distribution_id: Uuid,
	pub record: SenderKeyRecordStructure,
}