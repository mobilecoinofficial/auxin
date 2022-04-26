#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WebSocketRequestMessage {
    #[prost(string, optional, tag="1")]
    pub verb: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub path: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bytes="vec", optional, tag="3")]
    pub body: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(string, repeated, tag="5")]
    pub headers: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(uint64, optional, tag="4")]
    pub id: ::core::option::Option<u64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WebSocketResponseMessage {
    #[prost(uint64, optional, tag="1")]
    pub id: ::core::option::Option<u64>,
    #[prost(uint32, optional, tag="2")]
    pub status: ::core::option::Option<u32>,
    #[prost(string, optional, tag="3")]
    pub message: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="5")]
    pub headers: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(bytes="vec", optional, tag="4")]
    pub body: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WebSocketMessage {
    #[prost(enumeration="web_socket_message::Type", optional, tag="1")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(message, optional, tag="2")]
    pub request: ::core::option::Option<WebSocketRequestMessage>,
    #[prost(message, optional, tag="3")]
    pub response: ::core::option::Option<WebSocketResponseMessage>,
}
/// Nested message and enum types in `WebSocketMessage`.
pub mod web_socket_message {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        Unknown = 0,
        Request = 1,
        Response = 2,
    }
}
