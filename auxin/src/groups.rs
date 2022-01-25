// Parts of this file are taken from whisperfish's libsignal-service-rs repository 
// at revision b0f5d4f928f0ab096c6e9d0d189c5560f93f77ff, 
// which is permitted as both projects are under the AGPL. 
// For reference please see https://github.com/whisperfish/libsignal-service-rs

use auxin_protos::{SenderKeyStateStructure, SenderChainKey, SenderSigningKey};
use libsignal_protocol::error::SignalProtocolError;
use protobuf::{CodedInputStream, ProtobufError, Message};
use ring::hmac;
use zkgroup::{groups::GroupMasterKey, PROFILE_KEY_LEN};
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
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zkgroup::{
    auth::AuthCredentialResponse,
    ServerPublicParams,
    groups::GroupSecretParams,
    profiles::{ProfileKey, ProfileKeyCredentialPresentation},
};

use crate::{net::{AuxinHttpsConnection, common_http_headers}, LocalIdentity, message::fix_protobuf_buf};

pub(crate) struct GroupOperations {
    group_secret_params: GroupSecretParams,
}

#[derive(Debug)]
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
impl std::fmt::Display for GroupDecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupDecryptionError::ZkGroupError(e) => write!(f, "Zero-knowledge group error: {:?}", e),
            GroupDecryptionError::BincodeError(e) => write!(f, "Bincode error while attempting to decrypt group: {:?}", e),
            GroupDecryptionError::ProtobufDecodeError(e) => write!(f, "Protobuf error while attempting to decrypt group: {:?}", e),
            GroupDecryptionError::WrongBlob => write!(f, "Wrong group attribute blob"),
        }
    }
}
impl std::error::Error for GroupDecryptionError {}

impl From<zkgroup::ZkGroupError> for GroupDecryptionError {
    fn from(e: zkgroup::ZkGroupError) -> Self {
        GroupDecryptionError::ZkGroupError(e)
    }
}

impl From<bincode::Error> for GroupDecryptionError {
    fn from(e: bincode::Error) -> Self {
        GroupDecryptionError::BincodeError(e)
    }
}

impl From<protobuf::ProtobufError> for GroupDecryptionError {
    fn from(e: protobuf::ProtobufError) -> Self {
        GroupDecryptionError::ProtobufDecodeError(e)
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
            .map_err(|e| GroupDecryptionError::ZkGroupError(e))?;
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
            let uuid = self.decrypt_uuid(&member.userId)?;
            let profile_key =
                self.decrypt_profile_key(&member.profileKey, uuid)?;
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
        result.joinedAtRevision = member.joinedAtRevision;
        Ok(result)
    }

    fn decrypt_pending_member(
        &self,
        member: EncryptedPendingMember,
    ) -> Result<DecryptedPendingMember, GroupDecryptionError> {
        let inner_member =
            member.member.as_ref().ok_or(GroupDecryptionError::WrongBlob)?;
        // "Unknown" UUID with zeroes in case of errors, see: UuidUtil.java:16
        let uuid = self.decrypt_uuid(&inner_member.userId).unwrap_or_default();
        let added_by = self.decrypt_uuid(&member.addedByUserId)?;

        let mut result = DecryptedPendingMember::default();
        result.uuid = uuid.to_vec();
        result.role = inner_member.role;
        result.addedByUuid = added_by.to_vec();
        result.timestamp = member.timestamp;
        result.uuidCipherText = inner_member.userId.clone();

        Ok(result)
    }

    fn decrypt_requesting_member(
        &self,
        member: EncryptedRequestingMember,
    ) -> Result<DecryptedRequestingMember, GroupDecryptionError> {
        let (uuid, profile_key) = if member.presentation.is_empty() {
            let uuid = self.decrypt_uuid(&member.userId)?;
            let profile_key =
                self.decrypt_profile_key(&member.profileKey, uuid)?;
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
            .map_err(|e| GroupDecryptionError::ZkGroupError(e))
            .and_then(|b| {
                //NOTE: This was written with Prost in mind, fix_protobuf_buf may be needed here. 
                let mut stream = CodedInputStream::from_bytes(&b[4..]);
                //Rust's type inference was confused by this, so I wrote it verbosely. 
                let out: Result<GroupAttributeBlob, ProtobufError> = stream.read_message();
                match out {
                    Ok(val) => Ok(val),
                    Err(e) => Err(GroupDecryptionError::ProtobufDecodeError(e)),
                }
            })
            .unwrap_or_else(|e: GroupDecryptionError| {
                log::warn!("Could not decrypt blob: {:?}", e);
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
                &group.disappearingMessagesTimer,
            );
        let members = group
            .members
            .into_iter()
            .map(|m| group_operations.decrypt_member(m))
            .collect::<Result<_, _>>()?;
        let pending_members = group
            .pendingMembers
            .into_iter()
            .map(|m| group_operations.decrypt_pending_member(m))
            .collect::<Result<_, _>>()?;
        let requesting_members = group
            .requestingMembers
            .into_iter()
            .map(|m| group_operations.decrypt_requesting_member(m))
            .collect::<Result<_, _>>()?;

        let mut result = DecryptedGroup::default();
        result.title = title;
        result.avatar = group.avatar;
        result.disappearingMessagesTimer = disappearing_messages_timer.into();
        result.accessControl = group.accessControl;
        result.revision = group.revision;
        result.members = members;
        result.pendingMembers = pending_members;
        result.requestingMembers = requesting_members;
        result.inviteLinkPassword = group.inviteLinkPassword;
        result.description = description;
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

#[derive(Debug, Clone, thiserror::Error)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpAuth {
    pub username: String,
    pub password: String,
}
impl HttpAuth { 
    pub fn make_auth_token(&self) -> String { 
		let mut auth_token = self.username.clone();
		auth_token.push(':');
		auth_token.push_str(&self.password);
		base64::encode(auth_token)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GroupApiError { 
    #[error("Error encountered while trying to make a request to Signal's web API for groups: {0}")]
    RequestError(String),
    #[error("Error encountered in response from an https request to Signal's web API for groups: {0}")]
    ResponseError(String),
    #[error("Could not use credentials cache for groups: {0}")]
    CredentialCache(CredentialsCacheError),
    #[error("Error parsing credentials response: {0}")]
    ParsingError(String),
    #[error("Groups v2 error")]
    GroupsV2Error,
    #[error("Bincode error: {0}")]
    BincodeError(String),
    #[error("Failed to decrypt group: {0}")]
    CouldNotDecrypt(#[from] GroupDecryptionError)
}

impl From<CredentialsCacheError> for GroupApiError {
    fn from(e: CredentialsCacheError) -> Self {
        GroupApiError::CredentialCache(e)
    }
}

impl From<Box<bincode::ErrorKind>> for GroupApiError {
    fn from(e: Box<bincode::ErrorKind>) -> Self {
        GroupApiError::BincodeError(format!("{:?}", e))
    }
}

pub struct GroupsManager<'a, N: AuxinHttpsConnection, C: CredentialsCache> {
    connection: &'a mut N,
    credentials: &'a mut C,
    local_identity: &'a LocalIdentity,
    server_public_params: ServerPublicParams,
}

impl<'a, N: AuxinHttpsConnection, C: CredentialsCache> GroupsManager<'a, N, C> {

    pub async fn get_authorization_for_today(&mut self,
        server_public_params: &mut ServerPublicParams,
        uuid: Uuid,
        group_secret_params: GroupSecretParams,
    ) -> Result<HttpAuth, GroupApiError> {
        let today = Self::current_time_days();
        let auth_credential_response = if let Some(auth_credential_response) =
            self.credentials.get(&today)?.clone()
        {
            auth_credential_response
        } else {
            let credentials_map =
                self.get_authorization(today).await?.parse()
                .map_err(|e| GroupApiError::ParsingError(format!("{:?}", e)))?;
            self.credentials.write(credentials_map)?;
            self.credentials.get(&today)?.ok_or_else(|| {
                GroupApiError::ResponseError(
                    "credentials received did not contain requested day".into()
                )
            })?
        };

        self.get_authorization_string(
            uuid,
            group_secret_params,
            auth_credential_response,
            today as u32,
        )
    }

    async fn get_authorization(&mut self,
        today: i64,
    ) -> Result<CredentialResponse, GroupApiError> {
        let today_plus_7_days = today + 7;

        let path = format!("https://textsecure-service.whispersystems.org/v1/certificate/group/{}/{}", today, today_plus_7_days);

        let auth_token = self.local_identity.make_auth_header();
        let req_builder = common_http_headers(http::Method::GET, path.as_str(), auth_token.as_str() ).unwrap();

        let req = req_builder.body(Vec::default()).unwrap();
        let response = self.connection.request(req).await
            .map_err(|e| GroupApiError::RequestError(format!("{:?}", e)))?;
        
        if !response.status().is_success() { 
            return Err(GroupApiError::ResponseError(format!("{:?}", response)) );
        }
        
        let body = response.body();
        Ok(
            serde_json::from_slice(body).map_err(|e| GroupApiError::ParsingError(format!("{:?}", e)))?
        )
    }

    fn current_time_days() -> i64 {
        //The number of (non-leap) seconds in days. Libsignal-service-rs also uses this so this must be the assumption Signal's servers are going on. 
        const SECONDS_PER_DAY: i64 = 60 * 60 * 24;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        (now.as_secs_f64() / (SECONDS_PER_DAY as f64)) as i64
    }

    fn get_authorization_string(&self,
        uuid: Uuid,
        group_secret_params: GroupSecretParams,
        credential_response: &AuthCredentialResponse,
        today: u32,
    ) -> Result<HttpAuth, GroupApiError> {
        let auth_credential = self.server_public_params
            .receive_auth_credential(
                *uuid.as_bytes(),
                today,
                credential_response,
            )
            .map_err(|e| {
                log::error!("zero-knowledge group error: {:?}", e);
                GroupApiError::GroupsV2Error
            })?;

        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);

        let auth_credential_presentation = self.server_public_params
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

    pub async fn get_group(&mut self,
        group_secret_params: GroupSecretParams,
        identity: &LocalIdentity,
        auth: &HttpAuth,
    ) -> Result<DecryptedGroup, GroupApiError> {
        let auth_token = auth.make_auth_token();
        //Per Signal-Android's repo, groupsv2 requests DO go to "storage.signal.org/v1/", confirmed. See PushServiceSocket.java#L232
        let req_builder = common_http_headers(http::Method::GET, "https://storage.signal.org/v1/groups/", auth_token.as_str() ).unwrap();
        let req = req_builder.body(Vec::default()).unwrap();
        let response = self.connection.request(req).await
            .map_err(|e| GroupApiError::RequestError(format!("{:?}", e)))?;
        
        if !response.status().is_success() { 
            return Err(GroupApiError::ResponseError(format!("{:?}", response)) );
        }
        let body = response.body();
        let fixed_body = fix_protobuf_buf(body).unwrap();
        let mut decoder = CodedInputStream::from_bytes(&fixed_body);
        let encrypted_group = decoder.read_message()
            .map_err(|e| GroupApiError::ParsingError(format!("Could not decode group response to a protobuf: {:?}", e)))?;
        let decrypted_group = GroupOperations::decrypt_group(
            group_secret_params,
            encrypted_group,
        )?;

        Ok(decrypted_group)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GroupIdError { 
    #[error("Error parsing group ID - valid sizes are 16 bytes for v1, or 32 bytes for v2. Instead, we got a group ID which is {0} bytes long. The group ID (in base-64) was: {1}")]
    InvalidSize(usize, String),
    #[error("Attempted to construct a GroupsV1 group ID but a GroupsV1 group ID is 16 bytes and the provided buffer was {0} bytes in size")]
    WrongSizeV1(usize),
    #[error("Attempted to construct a GroupsV2 group ID but a GroupsV2 group ID is 32 bytes and the provided buffer was {0} bytes in size")]
    WrongSizeV2(usize),
    #[error("Error parsing base64 into Group ID: {0:?}")]
    ParsingError(#[from] base64::DecodeError ),
}

pub enum GroupId { 
    V1([u8; 16]),
    V2([u8; 32]),
}

impl GroupId { 
    pub fn from_bytes_v1(val: &[u8]) -> Result<Self, GroupIdError> { 
        if val.len() != 16 { 
            Err(GroupIdError::WrongSizeV1(val.len()))
        }
        else {
            let mut buf: [u8;16] = [0;16];
            buf.copy_from_slice(&val[0..16]);
            Ok(GroupId::V1(buf))
        }
    }
    pub fn from_bytes_v2(val: &[u8]) -> Result<Self, GroupIdError> { 
        if val.len() != 32 { 
            Err(GroupIdError::WrongSizeV2(val.len()))
        }
        else {
            let mut buf: [u8;32] = [0;32];
            buf.copy_from_slice(&val[0..32]);
            Ok(GroupId::V2(buf))
        }
    }
    pub fn from_bytes(buffer: &Vec<u8>) -> Result<Self, GroupIdError>{ 
        if buffer.len() == 16 { 
            Ok(Self::from_bytes_v1(buffer.as_slice())?)
        }
        else if buffer.len() == 32 {
            Ok(Self::from_bytes_v2(buffer.as_slice())?)
        }
        else { 
            Err( GroupIdError::InvalidSize(buffer.len(), base64::encode(buffer)) )
        }
    }
    pub fn from_base64(b64: &str) -> Result<Self, GroupIdError>{
        let buf = base64::decode(b64)?;
        Ok(Self::from_bytes(&buf)?)
    }
}


#[derive(Debug, thiserror::Error)]
pub enum GroupUtilsError { 
    #[error("could not parse UUID: {0:?}")]
    UuidError(#[from] uuid::Error ),
    #[error("profile keys should be 32 bytes in size, but a group member with id {0:?} had a profile key which is {1} bytes.")]
    InvalidSizedProfileKey(Uuid, usize)
}

#[derive(Clone)]
pub struct GroupMemberInfo { 
    pub id: Uuid, 
    pub profile_key: Option<zkgroup::profiles::ProfileKey>,
    pub member_role: auxin_protos::protos::groups::Member_Role, 
    pub joined_at_revision: u32,
}

/// Ensure the Signal Service protocol buffer we got is valid and the data it contains is valid, 
/// producing a rearranged GroupMemberInfo struct with a deserialized UUID and (potentially) profile key
pub fn validate_group_member(group_member: &DecryptedMember) -> Result<GroupMemberInfo, GroupUtilsError> { 
    let uuid_bytes = group_member.get_uuid();
    let member_uuid = Uuid::from_slice(uuid_bytes)?;
    let pk_bytes = group_member.get_profileKey();
    let profile_key = if pk_bytes.len() == 32 { 
        let mut buffer: [u8; PROFILE_KEY_LEN] = [0; PROFILE_KEY_LEN];
        buffer.copy_from_slice(&pk_bytes[0..32]);
        let pk = ProfileKey::create(buffer);
        Some(pk)
    } else if pk_bytes.len() != 0 {
        // If it's not 32 bytes and not 0 bytes, this is invalid.
        return Err(GroupUtilsError::InvalidSizedProfileKey(member_uuid, pk_bytes.len()))
    } else { 
        None
    };

    Ok(GroupMemberInfo { 
        id: member_uuid, 
        profile_key, 
        member_role: group_member.get_role(),
        joined_at_revision: group_member.get_joinedAtRevision(),
    })
}

/// Returns results per-member, so that if invalid data is fetched for one user communication
/// with other users is not prevented.
pub fn get_group_members(group: &DecryptedGroup) -> Vec<Result<GroupMemberInfo, GroupUtilsError>> { 
    let mut result = Vec::new();
    for group_member in group.members.iter() { 
        result.push(
            validate_group_member(group_member)
        );
    }
    result
}
/// Get the list of group members from a decrypted group, skipping one result
/// This is used to elide our own local UUID from the list, to prevent the bot
/// from sending itself a message.
pub fn get_group_members_without(group: &DecryptedGroup, elide: &Uuid) -> Vec<Result<GroupMemberInfo, GroupUtilsError>> { 
    let mut result = get_group_members(&group); 
    result.retain(|value| {
        let elide_inner = elide.clone();
        match value { 
            Err(_) => true,
            Ok(elem) => elem.id != elide_inner
        }
    });
    result
}

// A SenderKey "name" is a (groupId + senderId + deviceId) tuple
// Most important point of reference is here: https://github.com/signalapp/libsignal-protocol-java/blob/fde96d22004f32a391554e4991e4e1f0a14c2d50/java/src/main/java/org/whispersystems/libsignal/groups/GroupCipher.java#L32

pub const MAX_SENDER_MESSAGE_KEYS: u64 = 2000;

const SENDER_MESSAGE_KEY_SEED: &'static [u8] = &[0x01];
const SENDER_CHAIN_KEY_SEED: &'static [u8]   = &[0x02];

/// Holds the state of an individual SenderKey ratchet.
pub struct SenderKeyState {
    pub structure: SenderKeyStateStructure,
}

impl SenderKeyState { 
    pub fn new(id: u32, iteration: u32, chain_key_bytes: &[u8],
            signature_key_public: libsignal_protocol::PublicKey,
            signature_key_private: Option<libsignal_protocol::PrivateKey>) -> Self {
        //Set up our chain key
        let mut chain_key = SenderChainKey::default();
        chain_key.set_iteration(iteration);
        chain_key.set_seed(chain_key_bytes.to_vec());
        protobuf::Message::compute_size(&mut chain_key);
        
        //Set up our signing key
        let mut signing_key = SenderSigningKey::default();
        signing_key.set_public(signature_key_public.serialize().to_vec());
        //Optionally, check for a private key (Is this a Sender Key we're issuing?)
        if let Some(private) = signature_key_private {
            signing_key.set_private(private.serialize().to_vec());
        }
        protobuf::Message::compute_size(&mut signing_key);

        //Wrap this all up. 
        let mut result = SenderKeyStateStructure::default();
        result.set_sender_key_id(id);
        result.set_sender_chain_key(chain_key);
        result.set_sender_signing_key(signing_key);
        protobuf::Message::compute_size(&mut result);

        SenderKeyState { 
            structure: result,
        }
    }
}

// Make it easy to convert between the underlying 
// type SenderKeyStateStructure and the wrapper SenderKeyState. 
impl From<SenderKeyStateStructure> for SenderKeyState {
    fn from(val: SenderKeyStateStructure) -> Self {
        SenderKeyState { 
            structure: val,
        }
    }
}
impl From<SenderKeyState> for SenderKeyStateStructure {
    fn from(val: SenderKeyState) -> Self {
        val.structure
    }
}

pub fn chain_key_derivative(seed: &[u8], key: &[u8]) -> Vec<u8> { 
    let digest_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
    let mut digest: hmac::Context = hmac::Context::with_key(&digest_key);

    //"Derivative" key is a hash of the seed. 
    digest.update(&seed);

    let tag = digest.sign();

    tag.as_ref().to_vec()
}

//Cannot define impl on types from other crates.
//We can use the usual Rust naming scheme here: {Type}Ext
pub trait SenderChainKeyExt { 
    fn get_seed<'a>(&'a self) -> &'a [u8];
    fn get_iteration(&self) -> u32;
    fn make_sender_message_key<'a>(&'a self) -> Result<SenderMessageKey, hkdf::InvalidLength> { 
        let derived_seed = chain_key_derivative( SENDER_MESSAGE_KEY_SEED, self.get_seed());
        
        SenderMessageKey::new(self.get_iteration(), &derived_seed)
    }
    fn make_next_chain<'a>(&'a self) -> SenderChainKey { 
        let derived_seed = chain_key_derivative( SENDER_CHAIN_KEY_SEED, self.get_seed());
        
        let mut result = SenderChainKey::default(); 
        //Increment "iteration" - this is the next one.
        result.set_iteration(self.get_iteration() + 1);
        result.set_seed(derived_seed);
        result.compute_size();
        result
    }
}

impl SenderChainKeyExt for SenderChainKey {
    fn get_seed<'a>(&'a self) -> &'a [u8] {
        SenderChainKey::get_seed(&self)
    }

    fn get_iteration(&self) -> u32 {
        self.iteration
    }
}

/* The final symmetric material (IV and Cipher Key) used for encrypting
 * individual SenderKey messages.
 */
pub struct SenderMessageKey {
    pub iteration: u32,
    pub seed: Vec<u8>, 
    pub iv: [u8; 16],
    pub cipher_key: [u8; 32],
}

impl SenderMessageKey { 
    pub fn new(iteration: u32, seed: &[u8]) -> Result<Self, hkdf::InvalidLength> { 

        let mut derivative: [u8; 48] = [0; 48]; 
        //Per usage in libsignal-protocol-java SenderMessageKey.java line 25, does not appear to use a salt. 
        hkdf::Hkdf::<sha2::Sha256>::new(None, seed)
            .expand(b"WhisperGroup", &mut derivative)?;
            
        let mut iv: [u8; 16] = [0;16];
        iv.copy_from_slice(&derivative[0..16]); 
        let mut cipher_key: [u8; 32] = [0;32];
        cipher_key.copy_from_slice(&derivative[16..48]); 
    
        Ok(SenderMessageKey {
            iteration,
            seed: seed.to_vec(),
            iv,
            cipher_key,
        })
    }
}

impl TryFrom<auxin_protos::SenderMessageKey> for SenderMessageKey {
    type Error = hkdf::InvalidLength;
    fn try_from(val: auxin_protos::SenderMessageKey) -> Result<Self, Self::Error> {
        Self::new(val.iteration, val.get_seed())
    }
}
impl From<SenderMessageKey> for auxin_protos::SenderMessageKey {
    fn from(val: SenderMessageKey) -> Self {
        let mut result = auxin_protos::SenderMessageKey::default();
        result.set_iteration(val.iteration);
        result.set_seed(val.seed);
        result
    }
}