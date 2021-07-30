pub use protobuf;

pub mod protos;

pub use protos::websocket::*;
pub use protos::signalservice::*;
pub use protos::sealed_sender::*;
pub use protos::storage::PreKeyRecordStructure;
pub use protos::storage::SignedPreKeyRecordStructure;

unsafe impl Send for WebSocketMessage {}
unsafe impl Send for WebSocketRequestMessage {}
unsafe impl Send for WebSocketResponseMessage {}