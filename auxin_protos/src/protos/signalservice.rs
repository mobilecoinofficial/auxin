#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Envelope {
    #[prost(enumeration="envelope::Type", optional, tag="1")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub source_e164: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="11")]
    pub source_uuid: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint32, optional, tag="7")]
    pub source_device: ::core::option::Option<u32>,
    #[prost(string, optional, tag="3")]
    pub relay: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint64, optional, tag="5")]
    pub timestamp: ::core::option::Option<u64>,
    /// Contains an encrypted DataMessage
    #[prost(bytes="vec", optional, tag="6")]
    pub legacy_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// Contains an encrypted Content
    #[prost(bytes="vec", optional, tag="8")]
    pub content: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(string, optional, tag="9")]
    pub server_guid: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint64, optional, tag="10")]
    pub server_timestamp: ::core::option::Option<u64>,
}
/// Nested message and enum types in `Envelope`.
pub mod envelope {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        Unknown = 0,
        Ciphertext = 1,
        KeyExchange = 2,
        PrekeyBundle = 3,
        Receipt = 5,
        UnidentifiedSender = 6,
        /// For GroupsV2
        SenderKey = 7,
        PlaintextContent = 8,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Content {
    #[prost(message, optional, tag="1")]
    pub data_message: ::core::option::Option<DataMessage>,
    #[prost(message, optional, tag="2")]
    pub sync_message: ::core::option::Option<SyncMessage>,
    #[prost(message, optional, tag="3")]
    pub call_message: ::core::option::Option<CallMessage>,
    #[prost(message, optional, tag="4")]
    pub null_message: ::core::option::Option<NullMessage>,
    #[prost(message, optional, tag="5")]
    pub receipt_message: ::core::option::Option<ReceiptMessage>,
    #[prost(message, optional, tag="6")]
    pub typing_message: ::core::option::Option<TypingMessage>,
    #[prost(bytes="vec", optional, tag="7")]
    pub sender_key_distribution_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", optional, tag="8")]
    pub decryption_error_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallMessage {
    #[prost(message, optional, tag="1")]
    pub offer: ::core::option::Option<call_message::Offer>,
    #[prost(message, optional, tag="2")]
    pub answer: ::core::option::Option<call_message::Answer>,
    #[prost(message, repeated, tag="3")]
    pub ice_update: ::prost::alloc::vec::Vec<call_message::IceUpdate>,
    #[prost(message, optional, tag="4")]
    pub legacy_hangup: ::core::option::Option<call_message::Hangup>,
    #[prost(message, optional, tag="5")]
    pub busy: ::core::option::Option<call_message::Busy>,
    #[prost(message, optional, tag="7")]
    pub hangup: ::core::option::Option<call_message::Hangup>,
    #[prost(bool, optional, tag="8")]
    pub multi_ring: ::core::option::Option<bool>,
    #[prost(uint32, optional, tag="9")]
    pub destination_device_id: ::core::option::Option<u32>,
    #[prost(message, optional, tag="10")]
    pub opaque: ::core::option::Option<call_message::Opaque>,
}
/// Nested message and enum types in `CallMessage`.
pub mod call_message {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Offer {
        #[prost(uint64, optional, tag="1")]
        pub id: ::core::option::Option<u64>,
        /// Legacy/deprecated; replaced by 'opaque'
        #[prost(string, optional, tag="2")]
        pub sdp: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(enumeration="offer::Type", optional, tag="3")]
        pub r#type: ::core::option::Option<i32>,
        #[prost(bytes="vec", optional, tag="4")]
        pub opaque: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    }
    /// Nested message and enum types in `Offer`.
    pub mod offer {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum Type {
            OfferAudioCall = 0,
            OfferVideoCall = 1,
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Answer {
        #[prost(uint64, optional, tag="1")]
        pub id: ::core::option::Option<u64>,
        /// Legacy/deprecated; replaced by 'opaque'
        #[prost(string, optional, tag="2")]
        pub sdp: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(bytes="vec", optional, tag="3")]
        pub opaque: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct IceUpdate {
        #[prost(uint64, optional, tag="1")]
        pub id: ::core::option::Option<u64>,
        /// Legacy/deprecated; remove when old clients are gone.
        #[prost(string, optional, tag="2")]
        pub mid: ::core::option::Option<::prost::alloc::string::String>,
        /// Legacy/deprecated; remove when old clients are gone.
        #[prost(uint32, optional, tag="3")]
        pub line: ::core::option::Option<u32>,
        /// Legacy/deprecated; replaced by 'opaque'
        #[prost(string, optional, tag="4")]
        pub sdp: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(bytes="vec", optional, tag="5")]
        pub opaque: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Busy {
        #[prost(uint64, optional, tag="1")]
        pub id: ::core::option::Option<u64>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Hangup {
        #[prost(uint64, optional, tag="1")]
        pub id: ::core::option::Option<u64>,
        #[prost(enumeration="hangup::Type", optional, tag="2")]
        pub r#type: ::core::option::Option<i32>,
        #[prost(uint32, optional, tag="3")]
        pub device_id: ::core::option::Option<u32>,
    }
    /// Nested message and enum types in `Hangup`.
    pub mod hangup {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum Type {
            HangupNormal = 0,
            HangupAccepted = 1,
            HangupDeclined = 2,
            HangupBusy = 3,
            HangupNeedPermission = 4,
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Opaque {
        #[prost(bytes="vec", optional, tag="1")]
        pub data: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DataMessage {
    #[prost(string, optional, tag="1")]
    pub body: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="2")]
    pub attachments: ::prost::alloc::vec::Vec<AttachmentPointer>,
    #[prost(message, optional, tag="3")]
    pub group: ::core::option::Option<GroupContext>,
    #[prost(message, optional, tag="15")]
    pub group_v2: ::core::option::Option<GroupContextV2>,
    #[prost(uint32, optional, tag="4")]
    pub flags: ::core::option::Option<u32>,
    #[prost(uint32, optional, tag="5")]
    pub expire_timer: ::core::option::Option<u32>,
    #[prost(bytes="vec", optional, tag="6")]
    pub profile_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint64, optional, tag="7")]
    pub timestamp: ::core::option::Option<u64>,
    #[prost(message, optional, tag="8")]
    pub quote: ::core::option::Option<data_message::Quote>,
    #[prost(message, repeated, tag="9")]
    pub contact: ::prost::alloc::vec::Vec<data_message::Contact>,
    #[prost(message, repeated, tag="10")]
    pub preview: ::prost::alloc::vec::Vec<data_message::Preview>,
    #[prost(message, optional, tag="11")]
    pub sticker: ::core::option::Option<data_message::Sticker>,
    #[prost(uint32, optional, tag="12")]
    pub required_protocol_version: ::core::option::Option<u32>,
    #[prost(bool, optional, tag="14")]
    pub is_view_once: ::core::option::Option<bool>,
    #[prost(message, optional, tag="16")]
    pub reaction: ::core::option::Option<data_message::Reaction>,
    #[prost(message, optional, tag="17")]
    pub delete: ::core::option::Option<data_message::Delete>,
    #[prost(message, repeated, tag="18")]
    pub body_ranges: ::prost::alloc::vec::Vec<data_message::BodyRange>,
    #[prost(message, optional, tag="19")]
    pub group_call_update: ::core::option::Option<data_message::GroupCallUpdate>,
    #[prost(message, optional, tag="20")]
    pub payment: ::core::option::Option<data_message::Payment>,
}
/// Nested message and enum types in `DataMessage`.
pub mod data_message {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BodyRange {
        #[prost(int32, optional, tag="1")]
        pub start: ::core::option::Option<i32>,
        #[prost(int32, optional, tag="2")]
        pub length: ::core::option::Option<i32>,
        #[prost(oneof="body_range::AssociatedValue", tags="3")]
        pub associated_value: ::core::option::Option<body_range::AssociatedValue>,
    }
    /// Nested message and enum types in `BodyRange`.
    pub mod body_range {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum AssociatedValue {
            #[prost(string, tag="3")]
            MentionUuid(::prost::alloc::string::String),
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Quote {
        #[prost(uint64, optional, tag="1")]
        pub id: ::core::option::Option<u64>,
        #[prost(string, optional, tag="2")]
        pub author_e164: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="5")]
        pub author_uuid: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="3")]
        pub text: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(message, repeated, tag="4")]
        pub attachments: ::prost::alloc::vec::Vec<quote::QuotedAttachment>,
        #[prost(message, repeated, tag="6")]
        pub body_ranges: ::prost::alloc::vec::Vec<BodyRange>,
    }
    /// Nested message and enum types in `Quote`.
    pub mod quote {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct QuotedAttachment {
            #[prost(string, optional, tag="1")]
            pub content_type: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="2")]
            pub file_name: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(message, optional, tag="3")]
            pub thumbnail: ::core::option::Option<super::super::AttachmentPointer>,
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Contact {
        #[prost(message, optional, tag="1")]
        pub name: ::core::option::Option<contact::Name>,
        #[prost(message, repeated, tag="3")]
        pub number: ::prost::alloc::vec::Vec<contact::Phone>,
        #[prost(message, repeated, tag="4")]
        pub email: ::prost::alloc::vec::Vec<contact::Email>,
        #[prost(message, repeated, tag="5")]
        pub address: ::prost::alloc::vec::Vec<contact::PostalAddress>,
        #[prost(message, optional, tag="6")]
        pub avatar: ::core::option::Option<contact::Avatar>,
        #[prost(string, optional, tag="7")]
        pub organization: ::core::option::Option<::prost::alloc::string::String>,
    }
    /// Nested message and enum types in `Contact`.
    pub mod contact {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Name {
            #[prost(string, optional, tag="1")]
            pub given_name: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="2")]
            pub family_name: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="3")]
            pub prefix: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="4")]
            pub suffix: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="5")]
            pub middle_name: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="6")]
            pub display_name: ::core::option::Option<::prost::alloc::string::String>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Phone {
            #[prost(string, optional, tag="1")]
            pub value: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(enumeration="phone::Type", optional, tag="2")]
            pub r#type: ::core::option::Option<i32>,
            #[prost(string, optional, tag="3")]
            pub label: ::core::option::Option<::prost::alloc::string::String>,
        }
        /// Nested message and enum types in `Phone`.
        pub mod phone {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
            #[repr(i32)]
            pub enum Type {
                Home = 1,
                Mobile = 2,
                Work = 3,
                Custom = 4,
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Email {
            #[prost(string, optional, tag="1")]
            pub value: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(enumeration="email::Type", optional, tag="2")]
            pub r#type: ::core::option::Option<i32>,
            #[prost(string, optional, tag="3")]
            pub label: ::core::option::Option<::prost::alloc::string::String>,
        }
        /// Nested message and enum types in `Email`.
        pub mod email {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
            #[repr(i32)]
            pub enum Type {
                Home = 1,
                Mobile = 2,
                Work = 3,
                Custom = 4,
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PostalAddress {
            #[prost(enumeration="postal_address::Type", optional, tag="1")]
            pub r#type: ::core::option::Option<i32>,
            #[prost(string, optional, tag="2")]
            pub label: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="3")]
            pub street: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="4")]
            pub pobox: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="5")]
            pub neighborhood: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="6")]
            pub city: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="7")]
            pub region: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="8")]
            pub postcode: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="9")]
            pub country: ::core::option::Option<::prost::alloc::string::String>,
        }
        /// Nested message and enum types in `PostalAddress`.
        pub mod postal_address {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
            #[repr(i32)]
            pub enum Type {
                Home = 1,
                Work = 2,
                Custom = 3,
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Avatar {
            #[prost(message, optional, tag="1")]
            pub avatar: ::core::option::Option<super::super::AttachmentPointer>,
            #[prost(bool, optional, tag="2")]
            pub is_profile: ::core::option::Option<bool>,
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Preview {
        #[prost(string, optional, tag="1")]
        pub url: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="2")]
        pub title: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(message, optional, tag="3")]
        pub image: ::core::option::Option<super::AttachmentPointer>,
        #[prost(string, optional, tag="4")]
        pub description: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(uint64, optional, tag="5")]
        pub date: ::core::option::Option<u64>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Sticker {
        #[prost(bytes="vec", optional, tag="1")]
        pub pack_id: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        #[prost(bytes="vec", optional, tag="2")]
        pub pack_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        #[prost(uint32, optional, tag="3")]
        pub sticker_id: ::core::option::Option<u32>,
        #[prost(message, optional, tag="4")]
        pub data: ::core::option::Option<super::AttachmentPointer>,
        #[prost(string, optional, tag="5")]
        pub emoji: ::core::option::Option<::prost::alloc::string::String>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Reaction {
        #[prost(string, optional, tag="1")]
        pub emoji: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(bool, optional, tag="2")]
        pub remove: ::core::option::Option<bool>,
        #[prost(string, optional, tag="4")]
        pub target_author_uuid: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(uint64, optional, tag="5")]
        pub target_sent_timestamp: ::core::option::Option<u64>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Delete {
        #[prost(uint64, optional, tag="1")]
        pub target_sent_timestamp: ::core::option::Option<u64>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GroupCallUpdate {
        #[prost(string, optional, tag="1")]
        pub era_id: ::core::option::Option<::prost::alloc::string::String>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Payment {
        #[prost(oneof="payment::Item", tags="1")]
        pub item: ::core::option::Option<payment::Item>,
    }
    /// Nested message and enum types in `Payment`.
    pub mod payment {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Address {
            #[prost(oneof="address::Address", tags="1")]
            pub address: ::core::option::Option<address::Address>,
        }
        /// Nested message and enum types in `Address`.
        pub mod address {
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct MobileCoin {
                #[prost(bytes="vec", optional, tag="1")]
                pub address: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
            }
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum Address {
                #[prost(message, tag="1")]
                MobileCoin(MobileCoin),
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Amount {
            #[prost(oneof="amount::Amount", tags="1")]
            pub amount: ::core::option::Option<amount::Amount>,
        }
        /// Nested message and enum types in `Amount`.
        pub mod amount {
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct MobileCoin {
                #[prost(uint64, optional, tag="1")]
                pub pico_mob: ::core::option::Option<u64>,
            }
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum Amount {
                #[prost(message, tag="1")]
                MobileCoin(MobileCoin),
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Notification {
            #[prost(string, optional, tag="2")]
            pub note: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(oneof="notification::Transaction", tags="1")]
            pub transaction: ::core::option::Option<notification::Transaction>,
        }
        /// Nested message and enum types in `Notification`.
        pub mod notification {
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct MobileCoin {
                #[prost(bytes="vec", optional, tag="1")]
                pub receipt: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
            }
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum Transaction {
                #[prost(message, tag="1")]
                MobileCoin(MobileCoin),
            }
        }
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Item {
            #[prost(message, tag="1")]
            Notification(Notification),
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Flags {
        EndSession = 1,
        ExpirationTimerUpdate = 2,
        ProfileKeyUpdate = 4,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ProtocolVersion {
        Initial = 0,
        MessageTimers = 1,
        ViewOnce = 2,
        ViewOnceVideo = 3,
        Reactions = 4,
        CdnSelectorAttachments = 5,
        Mentions = 6,
        Payments = 7,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NullMessage {
    #[prost(bytes="vec", optional, tag="1")]
    pub padding: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReceiptMessage {
    #[prost(enumeration="receipt_message::Type", optional, tag="1")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(uint64, repeated, packed="false", tag="2")]
    pub timestamp: ::prost::alloc::vec::Vec<u64>,
}
/// Nested message and enum types in `ReceiptMessage`.
pub mod receipt_message {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        Delivery = 0,
        Read = 1,
        Viewed = 2,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TypingMessage {
    #[prost(uint64, optional, tag="1")]
    pub timestamp: ::core::option::Option<u64>,
    #[prost(enumeration="typing_message::Action", optional, tag="2")]
    pub action: ::core::option::Option<i32>,
    #[prost(bytes="vec", optional, tag="3")]
    pub group_id: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// Nested message and enum types in `TypingMessage`.
pub mod typing_message {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Action {
        Started = 0,
        Stopped = 1,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Verified {
    #[prost(string, optional, tag="1")]
    pub destination_e164: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub destination_uuid: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bytes="vec", optional, tag="2")]
    pub identity_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(enumeration="verified::State", optional, tag="3")]
    pub state: ::core::option::Option<i32>,
    #[prost(bytes="vec", optional, tag="4")]
    pub null_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// Nested message and enum types in `Verified`.
pub mod verified {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum State {
        Default = 0,
        Verified = 1,
        Unverified = 2,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncMessage {
    #[prost(message, optional, tag="1")]
    pub sent: ::core::option::Option<sync_message::Sent>,
    #[prost(message, optional, tag="2")]
    pub contacts: ::core::option::Option<sync_message::Contacts>,
    #[prost(message, optional, tag="3")]
    pub groups: ::core::option::Option<sync_message::Groups>,
    #[prost(message, optional, tag="4")]
    pub request: ::core::option::Option<sync_message::Request>,
    #[prost(message, repeated, tag="5")]
    pub read: ::prost::alloc::vec::Vec<sync_message::Read>,
    #[prost(message, optional, tag="6")]
    pub blocked: ::core::option::Option<sync_message::Blocked>,
    #[prost(message, optional, tag="7")]
    pub verified: ::core::option::Option<Verified>,
    #[prost(message, optional, tag="9")]
    pub configuration: ::core::option::Option<sync_message::Configuration>,
    #[prost(bytes="vec", optional, tag="8")]
    pub padding: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, repeated, tag="10")]
    pub sticker_pack_operation: ::prost::alloc::vec::Vec<sync_message::StickerPackOperation>,
    #[prost(message, optional, tag="11")]
    pub view_once_open: ::core::option::Option<sync_message::ViewOnceOpen>,
    #[prost(message, optional, tag="12")]
    pub fetch_latest: ::core::option::Option<sync_message::FetchLatest>,
    #[prost(message, optional, tag="13")]
    pub keys: ::core::option::Option<sync_message::Keys>,
    #[prost(message, optional, tag="14")]
    pub message_request_response: ::core::option::Option<sync_message::MessageRequestResponse>,
    #[prost(message, optional, tag="15")]
    pub outgoing_payment: ::core::option::Option<sync_message::OutgoingPayment>,
    #[prost(message, repeated, tag="16")]
    pub viewed: ::prost::alloc::vec::Vec<sync_message::Viewed>,
}
/// Nested message and enum types in `SyncMessage`.
pub mod sync_message {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Sent {
        #[prost(string, optional, tag="1")]
        pub destination_e164: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="7")]
        pub destination_uuid: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(uint64, optional, tag="2")]
        pub timestamp: ::core::option::Option<u64>,
        #[prost(message, optional, tag="3")]
        pub message: ::core::option::Option<super::DataMessage>,
        #[prost(uint64, optional, tag="4")]
        pub expiration_start_timestamp: ::core::option::Option<u64>,
        #[prost(message, repeated, tag="5")]
        pub unidentified_status: ::prost::alloc::vec::Vec<sent::UnidentifiedDeliveryStatus>,
        #[prost(bool, optional, tag="6", default="false")]
        pub is_recipient_update: ::core::option::Option<bool>,
    }
    /// Nested message and enum types in `Sent`.
    pub mod sent {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct UnidentifiedDeliveryStatus {
            #[prost(string, optional, tag="1")]
            pub destination_e164: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="3")]
            pub destination_uuid: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(bool, optional, tag="2")]
            pub unidentified: ::core::option::Option<bool>,
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Contacts {
        #[prost(message, optional, tag="1")]
        pub blob: ::core::option::Option<super::AttachmentPointer>,
        #[prost(bool, optional, tag="2", default="false")]
        pub complete: ::core::option::Option<bool>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Groups {
        #[prost(message, optional, tag="1")]
        pub blob: ::core::option::Option<super::AttachmentPointer>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Blocked {
        #[prost(string, repeated, tag="1")]
        pub numbers: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        #[prost(string, repeated, tag="3")]
        pub uuids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        #[prost(bytes="vec", repeated, tag="2")]
        pub group_ids: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Request {
        #[prost(enumeration="request::Type", optional, tag="1")]
        pub r#type: ::core::option::Option<i32>,
    }
    /// Nested message and enum types in `Request`.
    pub mod request {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum Type {
            Unknown = 0,
            Contacts = 1,
            Groups = 2,
            Blocked = 3,
            Configuration = 4,
            Keys = 5,
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Read {
        #[prost(string, optional, tag="1")]
        pub sender_e164: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="3")]
        pub sender_uuid: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(uint64, optional, tag="2")]
        pub timestamp: ::core::option::Option<u64>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Viewed {
        #[prost(string, optional, tag="1")]
        pub sender_e164: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="3")]
        pub sender_uuid: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(uint64, optional, tag="2")]
        pub timestamp: ::core::option::Option<u64>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Configuration {
        #[prost(bool, optional, tag="1")]
        pub read_receipts: ::core::option::Option<bool>,
        #[prost(bool, optional, tag="2")]
        pub unidentified_delivery_indicators: ::core::option::Option<bool>,
        #[prost(bool, optional, tag="3")]
        pub typing_indicators: ::core::option::Option<bool>,
        #[prost(uint32, optional, tag="5")]
        pub provisioning_version: ::core::option::Option<u32>,
        #[prost(bool, optional, tag="6")]
        pub link_previews: ::core::option::Option<bool>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct StickerPackOperation {
        #[prost(bytes="vec", optional, tag="1")]
        pub pack_id: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        #[prost(bytes="vec", optional, tag="2")]
        pub pack_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        #[prost(enumeration="sticker_pack_operation::Type", optional, tag="3")]
        pub r#type: ::core::option::Option<i32>,
    }
    /// Nested message and enum types in `StickerPackOperation`.
    pub mod sticker_pack_operation {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum Type {
            Install = 0,
            Remove = 1,
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ViewOnceOpen {
        #[prost(string, optional, tag="1")]
        pub sender_e164: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="3")]
        pub sender_uuid: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(uint64, optional, tag="2")]
        pub timestamp: ::core::option::Option<u64>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FetchLatest {
        #[prost(enumeration="fetch_latest::Type", optional, tag="1")]
        pub r#type: ::core::option::Option<i32>,
    }
    /// Nested message and enum types in `FetchLatest`.
    pub mod fetch_latest {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum Type {
            Unknown = 0,
            LocalProfile = 1,
            StorageManifest = 2,
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Keys {
        #[prost(bytes="vec", optional, tag="1")]
        pub storage_service: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MessageRequestResponse {
        #[prost(string, optional, tag="1")]
        pub thread_e164: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="2")]
        pub thread_uuid: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(bytes="vec", optional, tag="3")]
        pub group_id: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        #[prost(enumeration="message_request_response::Type", optional, tag="4")]
        pub r#type: ::core::option::Option<i32>,
    }
    /// Nested message and enum types in `MessageRequestResponse`.
    pub mod message_request_response {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum Type {
            Unknown = 0,
            Accept = 1,
            Delete = 2,
            Block = 3,
            BlockAndDelete = 4,
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct OutgoingPayment {
        #[prost(string, optional, tag="1")]
        pub recipient_uuid: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="2")]
        pub note: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(oneof="outgoing_payment::PaymentDetail", tags="3")]
        pub payment_detail: ::core::option::Option<outgoing_payment::PaymentDetail>,
    }
    /// Nested message and enum types in `OutgoingPayment`.
    pub mod outgoing_payment {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct MobileCoin {
            #[prost(bytes="vec", optional, tag="1")]
            pub recipient_address: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
            /// @required
            #[prost(uint64, optional, tag="2")]
            pub amount_pico_mob: ::core::option::Option<u64>,
            /// @required
            #[prost(uint64, optional, tag="3")]
            pub fee_pico_mob: ::core::option::Option<u64>,
            #[prost(bytes="vec", optional, tag="4")]
            pub receipt: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
            #[prost(uint64, optional, tag="5")]
            pub ledger_block_timestamp: ::core::option::Option<u64>,
            /// @required
            #[prost(uint64, optional, tag="6")]
            pub ledger_block_index: ::core::option::Option<u64>,
            #[prost(bytes="vec", repeated, tag="7")]
            pub spent_key_images: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
            #[prost(bytes="vec", repeated, tag="8")]
            pub output_public_keys: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
        }
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum PaymentDetail {
            #[prost(message, tag="3")]
            MobileCoin(MobileCoin),
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AttachmentPointer {
    #[prost(string, optional, tag="2")]
    pub content_type: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bytes="vec", optional, tag="3")]
    pub key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint32, optional, tag="4")]
    pub size: ::core::option::Option<u32>,
    #[prost(bytes="vec", optional, tag="5")]
    pub thumbnail: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", optional, tag="6")]
    pub digest: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(string, optional, tag="7")]
    pub file_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint32, optional, tag="8")]
    pub flags: ::core::option::Option<u32>,
    #[prost(uint32, optional, tag="9")]
    pub width: ::core::option::Option<u32>,
    #[prost(uint32, optional, tag="10")]
    pub height: ::core::option::Option<u32>,
    #[prost(string, optional, tag="11")]
    pub caption: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="12")]
    pub blur_hash: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint64, optional, tag="13")]
    pub upload_timestamp: ::core::option::Option<u64>,
    /// Next ID: 16
    #[prost(uint32, optional, tag="14")]
    pub cdn_number: ::core::option::Option<u32>,
    #[prost(oneof="attachment_pointer::AttachmentIdentifier", tags="1, 15")]
    pub attachment_identifier: ::core::option::Option<attachment_pointer::AttachmentIdentifier>,
}
/// Nested message and enum types in `AttachmentPointer`.
pub mod attachment_pointer {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Flags {
        VoiceMessage = 1,
        Borderless = 2,
        Gif = 4,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum AttachmentIdentifier {
        #[prost(fixed64, tag="1")]
        CdnId(u64),
        #[prost(string, tag="15")]
        CdnKey(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupContext {
    #[prost(bytes="vec", optional, tag="1")]
    pub id: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(enumeration="group_context::Type", optional, tag="2")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(string, optional, tag="3")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="4")]
    pub members_e164: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="6")]
    pub members: ::prost::alloc::vec::Vec<group_context::Member>,
    #[prost(message, optional, tag="5")]
    pub avatar: ::core::option::Option<AttachmentPointer>,
}
/// Nested message and enum types in `GroupContext`.
pub mod group_context {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Member {
        #[prost(string, optional, tag="2")]
        pub e164: ::core::option::Option<::prost::alloc::string::String>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        Unknown = 0,
        Update = 1,
        Deliver = 2,
        Quit = 3,
        RequestInfo = 4,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupContextV2 {
    #[prost(bytes="vec", optional, tag="1")]
    pub master_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint32, optional, tag="2")]
    pub revision: ::core::option::Option<u32>,
    #[prost(bytes="vec", optional, tag="3")]
    pub group_change: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContactDetails {
    #[prost(string, optional, tag="1")]
    pub number: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="9")]
    pub uuid: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="3")]
    pub avatar: ::core::option::Option<contact_details::Avatar>,
    #[prost(string, optional, tag="4")]
    pub color: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="5")]
    pub verified: ::core::option::Option<Verified>,
    #[prost(bytes="vec", optional, tag="6")]
    pub profile_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bool, optional, tag="7")]
    pub blocked: ::core::option::Option<bool>,
    #[prost(uint32, optional, tag="8")]
    pub expire_timer: ::core::option::Option<u32>,
    #[prost(uint32, optional, tag="10")]
    pub inbox_position: ::core::option::Option<u32>,
    #[prost(bool, optional, tag="11")]
    pub archived: ::core::option::Option<bool>,
}
/// Nested message and enum types in `ContactDetails`.
pub mod contact_details {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Avatar {
        #[prost(string, optional, tag="1")]
        pub content_type: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(uint32, optional, tag="2")]
        pub length: ::core::option::Option<u32>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupDetails {
    #[prost(bytes="vec", optional, tag="1")]
    pub id: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(string, optional, tag="2")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="3")]
    pub members_e164: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="9")]
    pub members: ::prost::alloc::vec::Vec<group_details::Member>,
    #[prost(message, optional, tag="4")]
    pub avatar: ::core::option::Option<group_details::Avatar>,
    #[prost(bool, optional, tag="5", default="true")]
    pub active: ::core::option::Option<bool>,
    #[prost(uint32, optional, tag="6")]
    pub expire_timer: ::core::option::Option<u32>,
    #[prost(string, optional, tag="7")]
    pub color: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="8")]
    pub blocked: ::core::option::Option<bool>,
    #[prost(uint32, optional, tag="10")]
    pub inbox_position: ::core::option::Option<u32>,
    #[prost(bool, optional, tag="11")]
    pub archived: ::core::option::Option<bool>,
}
/// Nested message and enum types in `GroupDetails`.
pub mod group_details {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Avatar {
        #[prost(string, optional, tag="1")]
        pub content_type: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(uint32, optional, tag="2")]
        pub length: ::core::option::Option<u32>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Member {
        #[prost(string, optional, tag="2")]
        pub e164: ::core::option::Option<::prost::alloc::string::String>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PaymentAddress {
    #[prost(oneof="payment_address::Address", tags="1")]
    pub address: ::core::option::Option<payment_address::Address>,
}
/// Nested message and enum types in `PaymentAddress`.
pub mod payment_address {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MobileCoinAddress {
        #[prost(bytes="vec", optional, tag="1")]
        pub address: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        #[prost(bytes="vec", optional, tag="2")]
        pub signature: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Address {
        #[prost(message, tag="1")]
        MobileCoinAddress(MobileCoinAddress),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptionErrorMessage {
    #[prost(bytes="vec", optional, tag="1")]
    pub ratchet_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint64, optional, tag="2")]
    pub timestamp: ::core::option::Option<u64>,
    #[prost(uint32, optional, tag="3")]
    pub device_id: ::core::option::Option<u32>,
}
