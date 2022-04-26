#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionStructure {
    #[prost(uint32, tag="1")]
    pub session_version: u32,
    #[prost(bytes="vec", tag="2")]
    pub local_identity_public: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="3")]
    pub remote_identity_public: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="4")]
    pub root_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="5")]
    pub previous_counter: u32,
    #[prost(message, optional, tag="6")]
    pub sender_chain: ::core::option::Option<session_structure::Chain>,
    #[prost(message, repeated, tag="7")]
    pub receiver_chains: ::prost::alloc::vec::Vec<session_structure::Chain>,
    #[prost(message, optional, tag="8")]
    pub pending_key_exchange: ::core::option::Option<session_structure::PendingKeyExchange>,
    #[prost(message, optional, tag="9")]
    pub pending_pre_key: ::core::option::Option<session_structure::PendingPreKey>,
    #[prost(uint32, tag="10")]
    pub remote_registration_id: u32,
    #[prost(uint32, tag="11")]
    pub local_registration_id: u32,
    #[prost(bool, tag="12")]
    pub needs_refresh: bool,
    #[prost(bytes="vec", tag="13")]
    pub alice_base_key: ::prost::alloc::vec::Vec<u8>,
}
/// Nested message and enum types in `SessionStructure`.
pub mod session_structure {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Chain {
        #[prost(bytes="vec", tag="1")]
        pub sender_ratchet_key: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="2")]
        pub sender_ratchet_key_private: ::prost::alloc::vec::Vec<u8>,
        #[prost(message, optional, tag="3")]
        pub chain_key: ::core::option::Option<chain::ChainKey>,
        #[prost(message, repeated, tag="4")]
        pub message_keys: ::prost::alloc::vec::Vec<chain::MessageKey>,
    }
    /// Nested message and enum types in `Chain`.
    pub mod chain {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ChainKey {
            #[prost(uint32, tag="1")]
            pub index: u32,
            #[prost(bytes="vec", tag="2")]
            pub key: ::prost::alloc::vec::Vec<u8>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct MessageKey {
            #[prost(uint32, tag="1")]
            pub index: u32,
            #[prost(bytes="vec", tag="2")]
            pub cipher_key: ::prost::alloc::vec::Vec<u8>,
            #[prost(bytes="vec", tag="3")]
            pub mac_key: ::prost::alloc::vec::Vec<u8>,
            #[prost(bytes="vec", tag="4")]
            pub iv: ::prost::alloc::vec::Vec<u8>,
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PendingKeyExchange {
        #[prost(uint32, tag="1")]
        pub sequence: u32,
        #[prost(bytes="vec", tag="2")]
        pub local_base_key: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="3")]
        pub local_base_key_private: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="4")]
        pub local_ratchet_key: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="5")]
        pub local_ratchet_key_private: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="7")]
        pub local_identity_key: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="8")]
        pub local_identity_key_private: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PendingPreKey {
        #[prost(uint32, tag="1")]
        pub pre_key_id: u32,
        #[prost(int32, tag="3")]
        pub signed_pre_key_id: i32,
        #[prost(bytes="vec", tag="2")]
        pub base_key: ::prost::alloc::vec::Vec<u8>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecordStructure {
    #[prost(message, optional, tag="1")]
    pub current_session: ::core::option::Option<SessionStructure>,
    #[prost(message, repeated, tag="2")]
    pub previous_sessions: ::prost::alloc::vec::Vec<SessionStructure>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreKeyRecordStructure {
    #[prost(uint32, tag="1")]
    pub id: u32,
    #[prost(bytes="vec", tag="2")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="3")]
    pub private_key: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignedPreKeyRecordStructure {
    #[prost(uint32, tag="1")]
    pub id: u32,
    #[prost(bytes="vec", tag="2")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="3")]
    pub private_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(fixed64, tag="5")]
    pub timestamp: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IdentityKeyPairStructure {
    #[prost(bytes="vec", tag="1")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub private_key: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SenderKeyStateStructure {
    #[prost(uint32, tag="1")]
    pub sender_key_id: u32,
    #[prost(message, optional, tag="2")]
    pub sender_chain_key: ::core::option::Option<sender_key_state_structure::SenderChainKey>,
    #[prost(message, optional, tag="3")]
    pub sender_signing_key: ::core::option::Option<sender_key_state_structure::SenderSigningKey>,
    #[prost(message, repeated, tag="4")]
    pub sender_message_keys: ::prost::alloc::vec::Vec<sender_key_state_structure::SenderMessageKey>,
}
/// Nested message and enum types in `SenderKeyStateStructure`.
pub mod sender_key_state_structure {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SenderChainKey {
        #[prost(uint32, tag="1")]
        pub iteration: u32,
        #[prost(bytes="vec", tag="2")]
        pub seed: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SenderMessageKey {
        #[prost(uint32, tag="1")]
        pub iteration: u32,
        #[prost(bytes="vec", tag="2")]
        pub seed: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SenderSigningKey {
        #[prost(bytes="vec", tag="1")]
        pub public: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="2")]
        pub private: ::prost::alloc::vec::Vec<u8>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SenderKeyRecordStructure {
    #[prost(message, repeated, tag="1")]
    pub sender_key_states: ::prost::alloc::vec::Vec<SenderKeyStateStructure>,
}
