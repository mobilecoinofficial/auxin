pub use protobuf;

pub mod protos;

pub use protos::{
	sealed_sender::*,
	signalservice::*,
	storage::{PreKeyRecordStructure, SignedPreKeyRecordStructure},
	websocket::*,
};

unsafe impl Send for WebSocketMessage {}
unsafe impl Send for WebSocketRequestMessage {}
unsafe impl Send for WebSocketResponseMessage {}
