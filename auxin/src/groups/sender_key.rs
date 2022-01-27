use aes_gcm::aead::generic_array::sequence::Shorten;
use auxin_protos::{SenderKeyStateStructure, SenderKeyRecordStructure, SenderChainKey, SenderSigningKey};
use libsignal_protocol::{DeviceId, SenderKeyDistributionMessage};

// A SenderKey "name" is a (groupId + senderId + deviceId) tuple
// Most important point of reference is here: https://github.com/signalapp/libsignal-protocol-java/blob/fde96d22004f32a391554e4991e4e1f0a14c2d50/java/src/main/java/org/whispersystems/libsignal/groups/GroupCipher.java#L32

#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub struct SenderKeyName { 
    group_id: GroupId, 
    address: AuxinAddress,
    device_id: DeviceId, // Just a u32
}

pub const MAX_SENDER_MESSAGE_KEYS: u64 = 2000;

const SENDER_MESSAGE_KEY_SEED: &'static [u8] = &[0x01];
const SENDER_CHAIN_KEY_SEED: &'static [u8]   = &[0x02];

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
    pub fn get_state_id(&self) -> u32 { 
        self.structure.get_sender_key_id()
    }
    pub fn get_key_id(&self) -> Uuid { 
        self.structure
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

#[derive(Debug)] //, thiserror::Error)]
pub enum SenderKeyStorageError { 
    /*#[error("Error encountered while trying to make a request to Signal's web API for groups: {0}")]
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
    CouldNotDecrypt(#[from] GroupDecryptionError)*/
}

pub const MAX_SENDER_KEY_RECORD_STATES: usize = 5;

/// A durable representation of a set of SenderKeyStates for a specific SenderKeyName.
pub struct SenderKeyRecord {
    states: VecDeque<SenderKeyState>,
}
impl SenderKeyRecord { 

    pub fn new() -> Self { 
        SenderKeyRecord { 
            states: Vec::default(),
        }
    }

    pub fn parse(serialized: &[u8]) -> Result<Self, SenderKeyStorageError> {
        let reader = CodedInputStream::from_bytes(serialized); 
        let record_structure: SenderKeyRecordStructure = reader.read_message()?;

        let states: Vec<SenderKeyState> = Vec::default();
        for structure in record_structure.get_sender_key_states() {
            states.push( structure.into() );
        }
        Ok( Self {
            states,
        } )
    }

    pub fn is_empty(&self) -> bool {
        self.states.empty()
    }

    pub fn get_newest_key_state(&self) -> Option<&SenderKeyState> {
        self.states.front()
    }

    pub fn get_key_state(&self, key_id: u32) -> Option<&SenderKeyState> {
        for state in self.states.iter() {
            if state.get_key_id() == key_id {
                return Some(state.clone);
            }
        }
        None
    }

    pub fn add_key_state(&mut self, id: u32, iteration: u32, chain_key_bytes: &[u8], signature_key: &libsignal_protocol::PublicKey) {
        self.states.push_front(SenderKeyState::new(id, iteration, chain_key_bytes, signature_key, None));

        // Keep it within MAX_SENDER_KEY_RECORD_STATES
        if self.states.len() > MAX_SENDER_KEY_RECORD_STATES {
            self.states.pop_back();
        }
    }

    /// Clears the list of key states and pushes one state to that list,
    /// such that it is guaranteed to be the returned value of get_newest_key_state() until
    /// add_key_state() is called again.
    pub fn rebuild_with_just_one(&mut self, id: u32, iteration: u32, chain_key_bytes: &[u8], signature_key: &libsignal_protocol::PublicKey) {
        senderKeyStates.clear();
        senderKeyStates.add(SenderKeyState::new(id, iteration, chain_key_bytes, signature_key, None));
    }

    pub fn serialize_to_proto(&self) -> SenderKeyRecordStructure {
        let mut structure = SenderKeyRecordStructure::default();

        for state in self.states.iter() {
            structure.mut_sender_key_states().push(state.clone().into());
        }

        structure
    }

    pub fn serialize_to_bytes(&self) -> Vec<u8> {
        let structure = self.serialize_to_proto();

        let mut serialized_structure: Vec<u8> = Vec::default();
		let mut writer = CodedOutputStream::vec(&mut serialized_structure);
		let _sz = protobuf::Message::compute_size(&content_message);

		protobuf::Message::write_to_with_cached_sizes(&structure, &mut outstream)?;
		outstream.flush()?;
		drop(outstream);

        serialized_structure
    }
}

pub struct SenderKeyStore {
    store: HashMap<SenderKeyName, SenderKeyRecord>,
}

impl SenderKeyStore {
    pub fn store_key(&mut self, name: SenderKeyName, record: SenderKeyRecord) {
        self.store.insert(name, record);
    }
    
    pub fn load_or_new_key(&self, name: &SenderKeyName) -> &SenderKeyRecord {
        match self.store.get(name) {
            Some(record) => record,
            None => { 
                let new_record = SenderKeyRecord::new();
                self.store.insert(name.clone(), new_record); 
                self.store.get(name).unwrap()
            }
        }
    }

    pub fn load_or_new_key_mut(&self, name: &SenderKeyName) -> &mut SenderKeyRecord {
        //Must be written less cleanly than load_or_new_key() for borrow checker reasons.
        //bool is Copy
        let has_record = self.store.contains(name);
    
        if has_record {
            self.store.get_mut(name).unwrap()
        } else { 
            let new_record = SenderKeyRecord::new();
            self.store.insert(name.clone(), new_record); 
            self.store.get_mut(name).unwrap()
        }
    }
}

pub const CURRENT_CIPHERTEXT_MESSAGE_VERSION: u32 = 3;

/// GroupSessionBuilder is responsible for setting up group SenderKey encrypted sessions.
/// Once a session has been established, GroupCipher can be used to encrypt/decrypt messages in that session.
/// The built sessions are unidirectional: they can be used either for sending or for receiving, but not both.
pub struct GroupSessionBuilder {
    sender_key_store: SenderKeyStore,
}

impl GroupSessionBuilder {
    pub fn new(sender_key_store: SenderKeyStore) -> Self { 
        GroupSessionBuilder { 
            sender_key_store,
        }
    }
    /// Construct a group session for receiving messages from senderKeyName.
	///
	/// # Arguments
	///
	/// * `sender_key_name` - The group id, sender id, and device id associated with the SenderKeyDistributionMessage.
	/// * `distribution_message` - A received SenderKeyDistributionMessage.
    pub fn process(&mut self, sender_key_name: SenderKeyName, distribution_message: SenderKeyDistributionMessage) {
        let mut record = self.sender_key_store.load_or_new_key_mut(&sender_key_name);
        record.add_key_state(distribution_message.get_id(),
        distribution_message.get_iteration(),
        distribution_message.get_chain_key(),
        distribution_message.get_signature_key());
    }
  
    /**
     * Construct a group session for sending messages.
     *
     * @param senderKeyName The (groupId, senderId, deviceId) tuple.  In this case, 'senderId' should be the caller.
     * @return A SenderKeyDistributionMessage that is individually distributed to each member of the group.
     */
    pub fn create_distribution_message(&mut self, sender_key_name: SenderKeyName) -> SenderKeyDistributionMessage {
        let mut record = self.sender_key_store.load_or_new_key_mut(senderKeyName);

        if record.is_empty() {
            record.rebuild_with_just_one(KeyHelper.generateSenderKeyId(),
            0,
            KeyHelper.generateSenderKey(),
            KeyHelper.generateSenderSigningKey());
        }

        //Should be impossible for this to be None per above record.is_empty() block, so unwrap
        let state = record.get_newest_key_state().unwrap();

        SenderKeyDistributionMessage::new(CURRENT_CIPHERTEXT_MESSAGE_VERSION,
            state.get,
            state.getSenderChainKey().getIteration(),
            state.getSenderChainKey().getSeed(),
            state.getSigningKeyPublic());
    }
  }
}