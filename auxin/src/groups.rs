// Parts of this file are taken from whisperfish's libsignal-service-rs repository 
// at revision b0f5d4f928f0ab096c6e9d0d189c5560f93f77ff, 
// which is permitted as both projects are under the AGPL. 
// For reference please see https://github.com/whisperfish/libsignal-service-rs

use libsignal_protocol::error::SignalProtocolError;
use protobuf::{UnknownFields, CodedInputStream};
use zkgroup::groups::GroupMasterKey;
use zkgroup::GROUP_MASTER_KEY_LEN;

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use auxin_protos::protos::{decrypted_groups::{
    DecryptedGroup, 
    DecryptedMember, 
    DecryptedPendingMember, 
    DecryptedRequestingMember,
    DecryptedTimer
}, groups::GroupAttributeBlob_oneof_content};

use auxin_protos::protos::groups::{
    Group as EncryptedGroup,
    Member as EncryptedMember,
    PendingMember as EncryptedPendingMember,
    RequestingMember as EncryptedRequestingMember,
    GroupAttributeBlob
};

use rand::RngCore;
use serde::Deserialize;
use uuid::Uuid;
use zkgroup::{
    auth::AuthCredentialResponse,
    ServerPublicParams,
    groups::GroupSecretParams,
    profiles::{ProfileKey, ProfileKeyCredentialPresentation},
};

pub(crate) struct GroupOperations {
    group_secret_params: GroupSecretParams,
}

pub enum GroupDecryptionError {
    //zero-knowledge group error
    ZkGroupError(zkgroup::ZkGroupError),
    //bincode::Error
    BincodeError(bincode::Error),
    //"protobuf message decoding error: {0}"
    ProtobufDecodeError(protobuf::ProtobufError),
    //"wrong group attribute blob"
    WrongBlob,
}

impl From<zkgroup::ZkGroupError> for GroupDecryptionError {
    fn from(e: zkgroup::ZkGroupError) -> Self {
        GroupDecryptionError::ZkGroupError(e)
    }
}

impl GroupOperations {
    fn decrypt_uuid(
        &self,
        uuid: &[u8],
    ) -> Result<[u8; 16], GroupDecryptionError> {
        let bytes = self
            .group_secret_params
            .decrypt_uuid(bincode::deserialize(uuid)?)
            .map_err(|_| GroupDecryptionError::ZkGroupError)?;
        Ok(bytes)
    }

    fn decrypt_profile_key(
        &self,
        profile_key: &[u8],
        decrypted_uuid: [u8; 16],
    ) -> Result<ProfileKey, GroupDecryptionError> {
        Ok(self.group_secret_params.decrypt_profile_key(
            bincode::deserialize(profile_key)?,
            decrypted_uuid,
        )?)
    }

    fn decrypt_member(
        &self,
        member: EncryptedMember,
    ) -> Result<DecryptedMember, GroupDecryptionError> {
        let (uuid, profile_key) = if member.presentation.is_empty() {
            let uuid = self.decrypt_uuid(&member.user_id)?;
            let profile_key =
                self.decrypt_profile_key(&member.profile_key, uuid)?;
            (uuid, profile_key)
        } else {
            let profile_key_credential_presentation: ProfileKeyCredentialPresentation = bincode::deserialize(&member.presentation)?;
            let uuid = self.group_secret_params.decrypt_uuid(
                profile_key_credential_presentation.get_uuid_ciphertext(),
            )?;
            let profile_key = self.group_secret_params.decrypt_profile_key(
                profile_key_credential_presentation
                    .get_profile_key_ciphertext(),
                uuid,
            )?;
            (uuid, profile_key)
        };
        let mut result = DecryptedMember::default();
        result.uuid = uuid.to_vec();
        result.role = member.role;
        result.profileKey = bincode::serialize(&profile_key)?;
        result.joinedAtRevision = member.joined_at_revision;
        Ok(result)
    }

    fn decrypt_pending_member(
        &self,
        member: EncryptedPendingMember,
    ) -> Result<DecryptedPendingMember, GroupDecryptionError> {
        let inner_member =
            member.member.ok_or(GroupDecryptionError::WrongBlob)?;
        // "Unknown" UUID with zeroes in case of errors, see: UuidUtil.java:16
        let uuid = self.decrypt_uuid(&inner_member.user_id).unwrap_or_default();
        let added_by = self.decrypt_uuid(&member.added_by_user_id)?;

        let mut result = DecryptedPendingMember::default();
        result.uuid = uuid.to_vec();
        result.role = inner_member.role;
        result.addedByUuid = added_by.to_vec();
        result.timestamp = member.timestamp;
        result.uuidCipherText = inner_member.user_id;

        Ok(result)
    }

    fn decrypt_requesting_member(
        &self,
        member: EncryptedRequestingMember,
    ) -> Result<DecryptedRequestingMember, GroupDecryptionError> {
        let (uuid, profile_key) = if member.presentation.is_empty() {
            let uuid = self.decrypt_uuid(&member.user_id)?;
            let profile_key =
                self.decrypt_profile_key(&member.profile_key, uuid)?;
            (uuid, profile_key)
        } else {
            let profile_key_credential_presentation: ProfileKeyCredentialPresentation = bincode::deserialize(&member.presentation)?;
            let uuid = self.group_secret_params.decrypt_uuid(
                profile_key_credential_presentation.get_uuid_ciphertext(),
            )?;
            let profile_key = self.group_secret_params.decrypt_profile_key(
                profile_key_credential_presentation
                    .get_profile_key_ciphertext(),
                uuid,
            )?;
            (uuid, profile_key)
        };
        let mut result = DecryptedRequestingMember::default();
        result.profileKey = bincode::serialize(&profile_key)?;
        result.uuid = uuid.to_vec();
        result.timestamp = member.timestamp;
        Ok(result)
    }

    fn decrypt_blob(&self, bytes: &[u8]) -> GroupAttributeBlob {
        if bytes.is_empty() {
            GroupAttributeBlob::default()
        } else if bytes.len() < 29 {
            log::warn!("bad encrypted blob length");
            GroupAttributeBlob::default()
        } else {
            self.group_secret_params
                .decrypt_blob(bytes)
                .map_err(|_| GroupDecryptionError::ZkGroupError)
                .and_then(|b| {
                    //NOTE: This was written with Prost in mind, fix_protobuf_buf may be needed here. 
                    CodedInputStream::from_bytes(&b[4..])
                    .map_err(GroupDecryptionError::ProtobufDecodeError)
                    .map(|stream| 
                        stream.read_message()
                        .map_err(GroupDecryptionError::ProtobufDecodeError) 
                    ).flatten()
                })
                .unwrap_or_else(|e| {
                    log::warn!("bad encrypted blob: {}", e);
                    GroupAttributeBlob::default()
                })
        }
    }

    fn decrypt_title(&self, ciphertext: &[u8]) -> String {
        match self.decrypt_blob(ciphertext).content {
            Some(GroupAttributeBlob_oneof_content::title(title)) => title,
            _ => "".into(), // TODO: return an error here?
        }
    }

    fn decrypt_description(&self, ciphertext: &[u8]) -> String {
        match self.decrypt_blob(ciphertext).content {
            Some(GroupAttributeBlob_oneof_content::description(description)) => description,
            _ => "".into(), // TODO: return an error here?
        }
    }

    fn decrypt_disappearing_message_timer(
        &self,
        ciphertext: &[u8],
    ) -> Option<DecryptedTimer> {
        match self.decrypt_blob(ciphertext).content {
            Some(GroupAttributeBlob_oneof_content::disappearingMessagesDuration(duration)) => {
                let mut result = DecryptedTimer::default(); 
                result.duration = duration; 
                Some(result)
            }
            _ => None,
        }
    }

    pub fn decrypt_group(
        group_secret_params: GroupSecretParams,
        group: EncryptedGroup,
    ) -> Result<DecryptedGroup, GroupDecryptionError> {
        let group_operations = Self {
            group_secret_params,
        };
        let title = group_operations.decrypt_title(&group.title);
        let description =
            group_operations.decrypt_description(&group.description);
        let disappearing_messages_timer = group_operations
            .decrypt_disappearing_message_timer(
                &group.disappearing_messages_timer,
            );
        let members = group
            .members
            .into_iter()
            .map(|m| group_operations.decrypt_member(m))
            .collect::<Result<_, _>>()?;
        let pending_members = group
            .pending_members
            .into_iter()
            .map(|m| group_operations.decrypt_pending_member(m))
            .collect::<Result<_, _>>()?;
        let requesting_members = group
            .requesting_members
            .into_iter()
            .map(|m| group_operations.decrypt_requesting_member(m))
            .collect::<Result<_, _>>()?;

        let mut result = DecryptedGroup::default();
        result.title = title;
        result.avatar = group.avatar;
        result.disappearing_messages_timer = DecryptedGroup::default();
        result.access_control = group.access_control;
        result.revision = group.revision;
        result.members = group.members;
        result.pending_members = group.pending_members;
        result.requesting_members = group.requestingMembers;
        result.inviteLinkPassword = group.invite_link_password;
        result.description = group.description;
        Ok(result)
    }
}
/// Given a 16-byte GroupV1 ID, derive the migration key.
///
/// Panics if the group_id is not 16 bytes long.
pub fn derive_v2_migration_master_key(
    group_id: &[u8],
) -> Result<GroupMasterKey, SignalProtocolError> {
    assert_eq!(group_id.len(), 16, "Group ID must be exactly 16 bytes");

    let mut bytes = [0; GROUP_MASTER_KEY_LEN];
    hkdf::Hkdf::<sha2::Sha256>::new(None, group_id)
        .expand(b"GV2 Migration", &mut bytes)
        .expect("valid output length");
    Ok(GroupMasterKey::new(bytes))
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemporalCredential {
    credential: String,
    redemption_time: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialResponse {
    credentials: Vec<TemporalCredential>,
}

impl CredentialResponse {
    pub fn parse(
        self,
    ) -> Result<HashMap<i64, AuthCredentialResponse>, Box<dyn std::error::Error> > {
        self.credentials
            .into_iter()
            .map(|c| {
                let bytes = base64::decode(c.credential)?;
                let data = bincode::deserialize(&bytes)?;
                Ok((c.redemption_time, data))
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialsCacheError {
    #[error("failed to read values from cache: {0}")]
    ReadError(String),
    #[error("failed to write values from cache: {0}")]
    WriteError(String),
}

/// Global cache for groups v2 credentials, as demonstrated in the libsignal-service
/// java library of Signal-Android.
///
/// A basic in-memory implementation is provided with `InMemoryCredentialsCache`.
pub trait CredentialsCache {
    fn clear(&mut self) -> Result<(), CredentialsCacheError>;

    /// Get an entry of the cache, key usually represents the day number since EPOCH.
    fn get(
        &self,
        key: &i64,
    ) -> Result<Option<&AuthCredentialResponse>, CredentialsCacheError>;

    /// Overwrite the entire contents of the cache with new data.
    fn write(
        &mut self,
        map: HashMap<i64, AuthCredentialResponse>,
    ) -> Result<(), CredentialsCacheError>;
}

#[derive(Default)]
pub struct InMemoryCredentialsCache {
    map: HashMap<i64, AuthCredentialResponse>,
}

impl CredentialsCache for InMemoryCredentialsCache {
    fn clear(&mut self) -> Result<(), CredentialsCacheError> {
        self.map.clear();
        Ok(())
    }

    fn get(
        &self,
        key: &i64,
    ) -> Result<Option<&AuthCredentialResponse>, CredentialsCacheError> {
        Ok(self.map.get(key))
    }

    fn write(
        &mut self,
        map: HashMap<i64, AuthCredentialResponse>,
    ) -> Result<(), CredentialsCacheError> {
        self.map = map;
        Ok(())
    }
}

pub struct GroupsManager<'a, S: PushService, C: CredentialsCache> {
    push_service: S,
    credentials_cache: &'a mut C,
    server_public_params: ServerPublicParams,
}

impl<'a, S: PushService, C: CredentialsCache> GroupsManager<'a, S, C> {
    pub fn new(
        push_service: S,
        credentials_cache: &'a mut C,
        server_public_params: ServerPublicParams,
    ) -> Self {
        Self {
            push_service,
            credentials_cache,
            server_public_params,
        }
    }

    pub async fn get_authorization_for_today(
        &mut self,
        uuid: Uuid,
        group_secret_params: GroupSecretParams,
    ) -> Result<HttpAuth, ServiceError> {
        let today = Self::current_time_days();
        let auth_credential_response = if let Some(auth_credential_response) =
            self.credentials_cache.get(&today)?
        {
            auth_credential_response
        } else {
            let credentials_map =
                self.get_authorization(today).await?.parse()?;
            self.credentials_cache.write(credentials_map)?;
            self.credentials_cache.get(&today)?.ok_or_else(|| {
                ServiceError::ResponseError {
                    reason:
                        "credentials received did not contain requested day"
                            .into(),
                }
            })?
        };

        self.get_authorization_string(
            uuid,
            group_secret_params,
            auth_credential_response,
            today as u32,
        )
    }

    async fn get_authorization(
        &mut self,
        today: i64,
    ) -> Result<CredentialResponse, ServiceError> {
        let today_plus_7_days = today + 7;

        let path =
            format!("/v1/certificate/group/{}/{}", today, today_plus_7_days);

        self.push_service
            .get_json(Endpoint::Service, &path, HttpAuthOverride::NoOverride)
            .await
    }

    fn current_time_days() -> i64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let today = chrono::Duration::from_std(now).unwrap();
        today.num_days()
    }

    fn get_authorization_string(
        &self,
        uuid: Uuid,
        group_secret_params: GroupSecretParams,
        credential_response: &AuthCredentialResponse,
        today: u32,
    ) -> Result<HttpAuth, ServiceError> {
        let auth_credential = self
            .server_public_params
            .receive_auth_credential(
                *uuid.as_bytes(),
                today,
                credential_response,
            )
            .map_err(|e| {
                log::error!("zero-knowledge group error: {:?}", e);
                ServiceError::GroupsV2Error
            })?;

        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);

        let auth_credential_presentation = self
            .server_public_params
            .create_auth_credential_presentation(
                random_bytes,
                group_secret_params,
                auth_credential,
            );

        // see simpleapi.rs GroupSecretParams_getPublicParams, everything is bincode encoded
        // across the boundary of Rust/Java
        let username = hex::encode(bincode::serialize(
            &group_secret_params.get_public_params(),
        )?);

        let password =
            hex::encode(bincode::serialize(&auth_credential_presentation)?);

        Ok(HttpAuth { username, password })
    }

    pub async fn get_group(
        &mut self,
        group_secret_params: GroupSecretParams,
        credentials: HttpAuth,
    ) -> Result<DecryptedGroup, ServiceError> {
        let encrypted_group = self.push_service.get_group(credentials).await?;
        let decrypted_group = GroupOperations::decrypt_group(
            group_secret_params,
            encrypted_group,
        )?;

        Ok(decrypted_group)
    }
}