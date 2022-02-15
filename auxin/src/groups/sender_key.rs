use std::collections::HashMap;

use auxin_protos::{SenderKeyStateStructure, SenderChainKey, SenderSigningKey};
use libsignal_protocol::{SenderKeyDistributionMessage, SignalProtocolError, SenderKeyRecord, SenderKeyStore};
use log::debug;
use protobuf::{Message, ProtobufError};
use rand::{Rng, CryptoRng};
use ring::hmac;
use uuid::Uuid;

use crate::{address::{AuxinDeviceAddress, AuxinAddress}, SignalCtx};

use super::GroupIdV2;

/// A DistributionId is a randomly-generated meaningless Uuid (also described as an opaque identifier) mapped to a GroupId internally in a Signal protocol implementation.
pub type DistributionId = Uuid;

pub fn generate_distribution_id() -> DistributionId { 
    Uuid::new_v4()
}

/// Any object with a 1-to-1 mapping to track which DistributionIds we have mapped to which GroupIds, and vice-versa
/// A given DistributionId will only ever point to one GroupId, so it's best to use DistributionId as the key and GroupId as the value.
pub trait DistributionIdStore { 
    fn get_group(&self, distribution_id: &DistributionId) -> Option<&GroupIdV2>; 
    fn get_distribution(&self, group_id: &GroupIdV2) -> Option<&DistributionId>;

    fn insert(&mut self, distribution_id: DistributionId, group_id: GroupIdV2);

    /// Retrieves a distribution id from this storage. 
    /// If none is present yet, it generates a new one, inserts the (GroupId, DistributionId) pair,
    /// and returns a reference to the newly-added DistributionId entry.
    fn get_or_generate_distribution_id(&mut self, group_id: &GroupIdV2) -> &DistributionId { 
        let has_record = self.get_distribution(group_id).is_some();
        if has_record {
            return self.get_distribution(group_id).unwrap();
        } else {
            let new_distribution = generate_distribution_id();
            self.insert(new_distribution, group_id.clone());
        }
        self.get_distribution(group_id).unwrap()
    }
}

impl DistributionIdStore for HashMap<DistributionId, GroupIdV2> {
    fn get_group(&self, distribution_id: &DistributionId) -> Option<&GroupIdV2> {
        self.get(distribution_id)
    }
    fn get_distribution(&self, group_id: &GroupIdV2) -> Option<&DistributionId> {
        for (distrib, matching_group) in self.iter() { 
            if group_id == matching_group { 
                return Some(distrib);
            }
        }
        None
    }
    fn insert(&mut self, distribution_id: DistributionId, group_id: GroupIdV2) {
        self.insert(distribution_id, group_id);
    }
}

// A SenderKey "name" is a (groupId + senderId + deviceId) tuple
// Most important point of reference is here: https://github.com/signalapp/libsignal-protocol-java/blob/fde96d22004f32a391554e4991e4e1f0a14c2d50/java/src/main/java/org/whispersystems/libsignal/groups/GroupCipher.java#L32
#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub struct SenderKeyName {
    pub distribution_id: DistributionId,
    pub sender: AuxinDeviceAddress,
}

impl Eq for SenderKeyName {}

pub const MAX_SENDER_MESSAGE_KEYS: u64 = 2000;

const SENDER_MESSAGE_KEY_SEED: &'static [u8] = &[0x01];
const SENDER_CHAIN_KEY_SEED: &'static [u8]   = &[0x02];

//Cannot define impl on types from other crates.
//We can use the usual Rust naming scheme here: {Type}Ext
pub trait SenderChainKeyExt { 
    fn get_seed<'a>(&'a self) -> &'a [u8];
    fn get_iteration(&self) -> u32;
    fn make_sender_message_key<'a>(&'a self) -> Result<SenderMessageKey, hkdf::InvalidLength> { 
        let derived_seed = chain_key_derivative( SENDER_MESSAGE_KEY_SEED, self.get_seed());
        
        SenderMessageKey::derive(self.get_iteration(), &derived_seed)
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

/// Holds the state of an individual SenderKey ratchet.
pub struct SenderKeyState {
    pub structure: SenderKeyStateStructure,
}

impl SenderKeyState { 
    pub fn new(id: u32, iteration: u32, chain_key_bytes: &[u8],
            signature_key_public: &libsignal_protocol::PublicKey,
            signature_key_private: Option<&libsignal_protocol::PrivateKey>) -> Self {
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
    pub fn get_key_id(&self) -> u32 { 
        self.structure.get_sender_key_id()
    }
    pub fn get_iteration(&self) -> u32 { 
        self.structure.get_sender_chain_key().get_iteration()
    }
    pub fn get_seed(&self) -> &[u8] { 
        self.structure.get_sender_chain_key().get_seed()
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
impl From<&SenderKeyState> for SenderKeyStateStructure {
    fn from(val: &SenderKeyState) -> Self {
        val.structure.clone()
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
    pub fn derive(iteration: u32, seed: &[u8]) -> Result<Self, hkdf::InvalidLength> { 

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
        Self::derive(val.iteration, val.get_seed())
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

#[derive(Debug, thiserror::Error)]
pub enum SenderKeyStorageError { 
    #[error("could not parse protobuf into sender key record: {0:?}")]
    ParseRecordError(ProtobufError),
}

pub const MAX_SENDER_KEY_RECORD_STATES: usize = 5;
pub const CIPHERTEXT_MESSAGE_VERSION: u8 = 3;

/// Load or initialize a key. 
pub async fn load_or_new_key<Store: SenderKeyStore>(sender_key_store: &mut Store, name: &SenderKeyName, ctx: &SignalCtx) -> Result<SenderKeyRecord, SignalProtocolError> {
    let protocol_address = name.sender.uuid_protocol_address().unwrap();
    let record_maybe = sender_key_store.load_sender_key(&protocol_address, name.distribution_id.clone(), ctx.get()).await?;

    if let Some(record) = record_maybe {
        Ok(record)
    } else { 
        let new_record = SenderKeyRecord::new_empty();
        sender_key_store.store_sender_key(&protocol_address, name.distribution_id.clone(), &new_record, ctx.get()).await?;
        Ok(new_record)
    }
}
/// Construct a group session for receiving messages from sender_key_name.
///
/// # Arguments
///
/// * `sender_key_name` - The group id, sender id, and device id associated with the SenderKeyDistributionMessage.
/// * `distribution_message` - A received SenderKeyDistributionMessage.
pub async fn process_sender_key<Store: SenderKeyStore>(sender_key_store: &mut Store, sender_key_name: SenderKeyName, distribution_message: SenderKeyDistributionMessage, ctx: &SignalCtx) -> Result<(), SignalProtocolError> {
    let mut record = load_or_new_key(sender_key_store, &sender_key_name, ctx).await?;
    record.add_sender_key_state(CIPHERTEXT_MESSAGE_VERSION,
        distribution_message.chain_id()?,
        distribution_message.iteration()?,
        distribution_message.chain_key()?,
        distribution_message.signing_key()?.clone(),
        None)?;

    let protocol_address = sender_key_name.sender.uuid_protocol_address().unwrap();
    sender_key_store.store_sender_key(&protocol_address, sender_key_name.distribution_id.clone(), &record, ctx.get()).await?;
    Ok(())
}

/// Construct a group session for sending messages.
///
/// # Arguments
///
/// * `sender_key_name` - The group id, sender id, and device id associated with the SenderKeyDistributionMessage. In this case, `address` should be the caller (i.e. the bot, the "self" user's address).
pub async fn create_distribution_message<R: Rng + CryptoRng, Store: SenderKeyStore>(sender_key_store: &mut Store, sender_key_name: &SenderKeyName, csprng: &mut R, signal_ctx: &SignalCtx) -> Result<SenderKeyDistributionMessage, SignalProtocolError> {
    let _record = load_or_new_key(sender_key_store, sender_key_name , signal_ctx).await?;
    let protocol_address = sender_key_name.sender.uuid_protocol_address().map_err(|_| { 
        SignalProtocolError::InvalidArgument(
            format!( "Could not creeate a sender key distribution message because this sender address cannot be used as a protocol address: {:?}", sender_key_name.sender )
        )
    })?;
    let distrib = libsignal_protocol::create_sender_key_distribution_message(&protocol_address, sender_key_name.distribution_id.clone(), sender_key_store, csprng, signal_ctx.get()).await?;
    Ok(distrib)
}

/// Stores and retrieves SenderKeys. 
/// Signal-protocol's InMemSenderKeyStore was unsuitable because there was no way to retrieve all currently-loaded keys at once, 
/// which makes it difficult to save all modified keys on exit. 
#[derive(Clone, Debug)]
pub struct AuxinSenderKeyStore { 
    pub sender_keys: HashMap<SenderKeyName, SenderKeyRecord>,
}

impl AuxinSenderKeyStore { 
    pub fn new() -> Self { 
        AuxinSenderKeyStore { 
            sender_keys: HashMap::default(),
        }
    }

    pub fn adjust_address_for_keystore(address: &AuxinDeviceAddress) -> AuxinDeviceAddress {
        if let Ok(uuid) = address.get_uuid() {
            AuxinDeviceAddress{ address: AuxinAddress::Uuid(uuid.clone()), device_id: address.device_id }
        }
        else {
            address.clone()
        }
    }

    pub fn import_sender_key(&mut self, sender_key_name: SenderKeyName, record: SenderKeyRecord) {
        let new_name = SenderKeyName{ sender: Self::adjust_address_for_keystore(&sender_key_name.sender), distribution_id: sender_key_name.distribution_id};
        self.sender_keys.insert(new_name, record);
    }
}
/// The type signatures here are so odd entirely so that we can implement this without relying on the async_trait crate. 
impl libsignal_protocol::SenderKeyStore for AuxinSenderKeyStore {
    fn store_sender_key< 'life0, 'life1, 'life2, 'async_trait>(& 'life0 mut self,sender: & 'life1 libsignal_protocol::ProtocolAddress,distribution_id:Uuid,record: & 'life2 libsignal_protocol::SenderKeyRecord, ctx:libsignal_protocol::Context,) ->  core::pin::Pin<Box<dyn core::future::Future<Output = libsignal_protocol::error::Result<()> > + 'async_trait> >where 'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait,Self: 'async_trait {
        let sender_key_name_maybe = sender.clone().try_into().map(|sender_auxin: AuxinDeviceAddress| {
            SenderKeyName{ sender: Self::adjust_address_for_keystore(&sender_auxin), distribution_id}
        });
        let result = match sender_key_name_maybe { 
            Ok(sender_key_name) => { 
                self.sender_keys.insert(sender_key_name, record.clone());
                Ok(())
            }
            Err(_) => Err(SignalProtocolError::InvalidArgument( format!("Invalid sender name, could not turn {} into a phone number or UUID.",sender.name()) )),
        };
        // Trick Libsignal_protocol into thinking this is async code and not sync code
        Box::pin( futures::future::ready(result) )
    }
    fn load_sender_key< 'life0, 'life1, 'async_trait>(& 'life0 mut self,sender: & 'life1 libsignal_protocol::ProtocolAddress,distribution_id:Uuid, ctx:libsignal_protocol::Context,) ->  core::pin::Pin<Box<dyn core::future::Future<Output = libsignal_protocol::error::Result<Option<libsignal_protocol::SenderKeyRecord> > > + 'async_trait> >where 'life0: 'async_trait, 'life1: 'async_trait,Self: 'async_trait {
        debug!("Looking up sender key from {:?} with distribution ID {}", sender, distribution_id.to_string());
        let sender_key_name_maybe = sender.clone().try_into().map(|sender_auxin: AuxinDeviceAddress| {
                SenderKeyName{ sender: Self::adjust_address_for_keystore(&sender_auxin), distribution_id}
            })
            .map_err(|_| {
                SignalProtocolError::InvalidArgument( format!("Invalid sender name, could not turn {} into a phone number or UUID.",sender.name() ) )
            });
        let result = sender_key_name_maybe.map(| name | { 
            self.sender_keys.get(&name)
                .map(|value| value.clone())
        });
        // Trick Libsignal_protocol into thinking this is async code and not sync code
        Box::pin( futures::future::ready(result) )
    }
}