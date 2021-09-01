pub use protobuf;

pub mod protos;

pub use protos::sealed_sender::*;
pub use protos::signalservice::*;
pub use protos::storage::PreKeyRecordStructure;
pub use protos::storage::SignedPreKeyRecordStructure;
pub use protos::websocket::*;

unsafe impl Send for WebSocketMessage {}
unsafe impl Send for WebSocketRequestMessage {}
unsafe impl Send for WebSocketResponseMessage {}
