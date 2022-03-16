use libsignal_protocol::{SignalProtocolError, group_encrypt, sealed_sender_encrypt_from_usmc, UnidentifiedSenderMessageContent, CiphertextMessageType, ContentHint};
use rand::{Rng, CryptoRng};
use uuid::Uuid;
use zkgroup::GROUP_MASTER_KEY_LEN;

use crate::{message::{MessageSendMode, envelope_types::EnvelopeType}, AuxinContext, address::AuxinDeviceAddress};

use super::{GroupApiError, sender_key::DistributionId};

pub type MasterKeyBytes = [u8; GROUP_MASTER_KEY_LEN];

pub enum GroupProtocolVersion {
    V1, 
    V2
}

#[derive(thiserror::Error, Debug)]
pub enum GroupEncryptionError {
	#[error("Could not generate a sealed-sender message to send to {0:?}: no \"Sender Certificate\" has been retrieved for this AuxinContext!")]
    NoSenderCertificate(AuxinDeviceAddress),
	#[error("Could not generate a UUID Protocol Address for our local instance! Our address is {0:?}")]
    OurProtocolAddress(AuxinDeviceAddress),
	#[error("Could not generate a UUID Protocol Address for selected recipient. Their address is {0:?}")]
    DestProtocolAddress(AuxinDeviceAddress),
	#[error("Group encryption error inside Signal protocol: {0:?}")]
    SignalProtocolError(#[from] SignalProtocolError),
}

#[derive(Clone, Debug)]
pub struct GroupSendContextV1 {
    //pub(crate) group_id: GroupIdV1,
}

#[derive(Clone, Debug)]
pub struct GroupSendContextV2 {
    //pub(crate) group_id: GroupIdV2,
    /// Group master key. Group ID can be derived from this, if necessary.
    pub(crate) master_key: MasterKeyBytes,
    /// Which opaque random Uuid have we associated with this group? 
    /// What distribution ID did we use to generate sender key distribution messages for this group?
    pub(crate) distribution_id: Uuid,
    pub(crate) revision: u32,
}

impl GroupSendContextV2 {
    /// Encrypt a sender_key message to this group.
    /// NOTE: This does not do any padding or serialization - it expects a buffer which 
    /// was built from a protobuf `Content` message and then padded.
    pub(crate) async fn sender_key_encrypt<R: Rng + CryptoRng>(&self, destination_address: &AuxinDeviceAddress, padded_plaintext: &[u8],
            context: &mut AuxinContext, rng: &mut R) -> Result<(EnvelopeType, Vec<u8>), GroupEncryptionError> {
        let our_address = context.identity.address.uuid_protocol_address()
            .map_err(|_| GroupEncryptionError::OurProtocolAddress(context.identity.address.clone()) )?;
        let is_sealed_sender = MessageSendMode::Standard;
        match is_sealed_sender {
            MessageSendMode::Standard => {
                let signal_ctx = context.get_signal_ctx().get();
                let ciphertext_message = libsignal_protocol::group_encrypt(&mut context.sender_key_store, &our_address, self.distribution_id.clone(), padded_plaintext, rng, signal_ctx).await?;
                Ok((EnvelopeType::SenderKey, ciphertext_message.serialized().to_vec()))
            },
            MessageSendMode::SealedSender => {
                let sender_cert_maybe = context.sender_certificate.clone();
                match sender_cert_maybe { 
                    Some(sender_certificate) => { 
                        let signal_ctx = context.get_signal_ctx().get();

                        let destination_protocol_address = destination_address.uuid_protocol_address()
                            .map_err(|_| GroupEncryptionError::DestProtocolAddress(destination_address.clone()) )?;
                        // First, encrypt a sender key message.  
                        let group_message = group_encrypt(
                            &mut context.sender_key_store,
                            &our_address,
                            self.distribution_id.clone(),
                            padded_plaintext,
                            rng,
                            signal_ctx,
                        ).await?;

                        let intermediary_usmc = UnidentifiedSenderMessageContent::new(
                            CiphertextMessageType::SenderKey,
                            sender_certificate,
                            group_message.serialized().to_vec(),
                            ContentHint::Default,
                            //Should there be a group ID here? In the test for sealed-sender group messages, there 
                            //was not, presumably due to Sealed Sender's anonymity properties.
                            None,
                        )?;
                
                        let resulting_ciphertext = sealed_sender_encrypt_from_usmc(
                            &destination_protocol_address,
                            &intermediary_usmc,
                            &mut context.identity_store,
                            signal_ctx,
                            rng,
                        ).await?;
                        Ok((EnvelopeType::SenderKey,resulting_ciphertext))
                    }, 
                    None => {
                        // Cannot set up a sealed_sender message without a SenderCertificate, so we must error out.
                        Err(GroupEncryptionError::NoSenderCertificate(destination_address.clone()))
                    }
                }
            }
        }
    }
}

/// Passed to message builder / message encryption methods to build an outgoing group message.
pub enum GroupSendContext { 
    V1(GroupSendContextV1),
    V2(GroupSendContextV2),
}

impl GroupSendContext {
    pub fn get_protocol_version(&self) -> GroupProtocolVersion { 
        match &self {
            GroupSendContext::V1(_) => GroupProtocolVersion::V1,
            GroupSendContext::V2(_) => GroupProtocolVersion::V2,
        }
    }
    pub fn add_group_data_to(&self, data_message: &mut auxin_protos::DataMessage) -> Result<(), GroupApiError> {
        match &self {
            GroupSendContext::V1(_inner) => {
                todo!("Legacy group message sending is not implemented yet.")
            },
            GroupSendContext::V2(inner) => {
                let mut groupv2 = auxin_protos::GroupContextV2::default();
                groupv2.set_masterKey(inner.master_key.to_vec());
                groupv2.set_revision(inner.revision); 
                protobuf::Message::compute_size(&groupv2);
                data_message.set_groupV2(groupv2)
            },
        }

        Ok(())
    }
    pub fn get_distribution_id(&self) -> Option<&DistributionId> {
        match &self {
            GroupSendContext::V1(_) => None, 
            GroupSendContext::V2(inner) => Some(&inner.distribution_id),
        }
    }
    pub async fn group_encrypt<R: Rng + CryptoRng>(&self, destination_address: &AuxinDeviceAddress, padded_plaintext: &[u8], 
            context: &mut AuxinContext, rng: &mut R) -> Result<(EnvelopeType, Vec<u8>), GroupEncryptionError> {
        match &self {
            GroupSendContext::V1(_inner) => todo!("Legacy group message sending is not implemented yet."),
            GroupSendContext::V2(inner) => inner.sender_key_encrypt(destination_address, padded_plaintext, context, rng).await,
        }
    }
}