// Copyright (c) 2022 MobileCoin Inc.
// Copyright (c) 2022 Emily Cultip

use std::collections::HashSet;

use auxin_protos::{Member_Role, SenderKeyRecordStructure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zkgroup::{profiles::ProfileKey, GROUP_MASTER_KEY_LEN, PROFILE_KEY_LEN};

use crate::{
	utils::{serde_base64, serde_optional_base64},
	Timestamp,
};

use super::GroupMemberInfo;

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct GroupMemberStorage {
	pub id: Uuid,
	#[serde(with = "serde_optional_base64")]
	pub profile_key: Option<Vec<u8>>,
	pub member_role: String,
	pub joined_at_revision: u32,
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
			"UNKNOWN" => Member_Role::UNKNOWN,
			"DEFAULT" => Member_Role::DEFAULT,
			"ADMINISTRATOR" => Member_Role::ADMINISTRATOR,
			not_role => {
				return Err(GroupSerializationError::NotARole(not_role.to_string()));
			}
		};
		Ok(Self {
			id: value.id,
			profile_key,
			member_role: role,
			joined_at_revision: value.joined_at_revision,
		})
	}
}

impl From<GroupMemberInfo> for GroupMemberStorage {
	fn from(value: GroupMemberInfo) -> Self {
		GroupMemberStorage {
			id: value.id,
			profile_key: value.profile_key.map(|pk| pk.bytes.to_vec()),
			member_role: match value.member_role {
				Member_Role::UNKNOWN => "UNKNOWN",
				Member_Role::DEFAULT => "DEFAULT",
				Member_Role::ADMINISTRATOR => "ADMINISTRATOR",
			}
			.to_string(),
			joined_at_revision: value.joined_at_revision,
		}
	}
}

#[derive(Clone)]
pub struct GroupInfo {
	pub revision: u32,
	pub master_key: [u8; GROUP_MASTER_KEY_LEN],
	pub members: HashSet<GroupMemberInfo>,
	/// What is the most recent distribution ID we made for this group?
	pub local_distribution_id: Option<Uuid>,
	pub last_distribution_timestamp: Timestamp,
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
	members: HashSet<GroupMemberStorage>,
	/// What is the most recent distribution ID we made for this group?
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
		let mut members = HashSet::new();
		for member in value.members.iter() {
			members.insert(member.clone().try_into()?);
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
		let mut members = HashSet::new();
		for member in value.members.iter() {
			members.insert(member.clone().into());
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
