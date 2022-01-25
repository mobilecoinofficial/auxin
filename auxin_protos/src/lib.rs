pub use protobuf;

pub mod protos;

pub use protos::{
	sealed_sender::*,
	signalservice::*,
	storage::*,
	websocket::*,
	groups::*,
	decrypted_groups::*,
};

pub use SenderKeyStateStructure_SenderChainKey as SenderChainKey;
pub use SenderKeyStateStructure_SenderMessageKey as SenderMessageKey;
pub use SenderKeyStateStructure_SenderSigningKey as SenderSigningKey;


unsafe impl Send for WebSocketMessage {}
unsafe impl Send for WebSocketRequestMessage {}
unsafe impl Send for WebSocketResponseMessage {}
