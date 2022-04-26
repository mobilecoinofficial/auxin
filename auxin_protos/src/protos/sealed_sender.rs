#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerCertificate {
    #[prost(bytes="vec", optional, tag="1")]
    pub certificate: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", optional, tag="2")]
    pub signature: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// Nested message and enum types in `ServerCertificate`.
pub mod server_certificate {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Certificate {
        #[prost(uint32, optional, tag="1")]
        pub id: ::core::option::Option<u32>,
        #[prost(bytes="vec", optional, tag="2")]
        pub key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SenderCertificate {
    #[prost(bytes="vec", optional, tag="1")]
    pub certificate: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", optional, tag="2")]
    pub signature: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// Nested message and enum types in `SenderCertificate`.
pub mod sender_certificate {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Certificate {
        #[prost(string, optional, tag="1")]
        pub sender_e164: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="6")]
        pub sender_uuid: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(uint32, optional, tag="2")]
        pub sender_device: ::core::option::Option<u32>,
        #[prost(fixed64, optional, tag="3")]
        pub expires: ::core::option::Option<u64>,
        #[prost(bytes="vec", optional, tag="4")]
        pub identity_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        #[prost(message, optional, tag="5")]
        pub signer: ::core::option::Option<super::ServerCertificate>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnidentifiedSenderMessage {
    #[prost(bytes="vec", optional, tag="1")]
    pub ephemeral_public: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", optional, tag="2")]
    pub encrypted_static: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", optional, tag="3")]
    pub encrypted_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// Nested message and enum types in `UnidentifiedSenderMessage`.
pub mod unidentified_sender_message {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Message {
        #[prost(enumeration="message::Type", optional, tag="1")]
        pub r#type: ::core::option::Option<i32>,
        #[prost(message, optional, tag="2")]
        pub sender_certificate: ::core::option::Option<super::SenderCertificate>,
        #[prost(bytes="vec", optional, tag="3")]
        pub content: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        #[prost(enumeration="message::ContentHint", optional, tag="4")]
        pub content_hint: ::core::option::Option<i32>,
        #[prost(bytes="vec", optional, tag="5")]
        pub group_id: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    }
    /// Nested message and enum types in `Message`.
    pub mod message {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum Type {
            PrekeyMessage = 1,
            Message = 2,
            /// Further cases should line up with Envelope.Type, even though old cases don't.
            ///reserved 3 to 6;
            SenderkeyMessage = 7,
            PlaintextContent = 8,
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum ContentHint {
            ///reserved     0; // Default: sender will not resend; an error should be shown immediately
            ///
            /// Sender will try to resend; delay any error UI if possible
            Resendable = 1,
            /// Don't show any error UI at all; this is something sent implicitly like a typing message or a receipt
            Implicit = 2,
        }
    }
}
