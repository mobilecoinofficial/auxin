use crate::app::App;
use async_global_executor::block_on;
use auxin::{
	address::{AuxinAddress, E164},
	message::{MessageOut},
	state::PeerInfoReply,
	AuxinReceiver,
};
use uuid::Uuid;

pub struct AppWrapper<'a> {
	pub app_inner: &'a mut App,
}

impl<'a> AppWrapper<'a> {
	/// Checks to see if a recipient's information is loaded and takes all actions necessary to fill out a PeerRecord if not.
	pub fn ensure_peer_loaded(&mut self, recipient_addr: &AuxinAddress) {
		block_on(self.app_inner.ensure_peer_loaded(recipient_addr)).unwrap()
	}
	pub fn send_message(&mut self, recipient_addr: &AuxinAddress, message: MessageOut) {
		block_on(self.app_inner.send_message(recipient_addr, message)).unwrap()
	}
	pub fn retrieve_sender_cert(&mut self) {
		block_on(self.app_inner.retrieve_sender_cert()).unwrap()
	}
	pub fn fill_peer_info(&mut self, recipient_addr: &AuxinAddress) {
		block_on(self.app_inner.fill_peer_info(recipient_addr)).unwrap()
	}
	pub fn retrieve_and_store_peer(&mut self, recipient_phone: &E164) {
		block_on(self.app_inner.retrieve_and_store_peer(recipient_phone)).unwrap()
	}
	pub fn request_peer_info(&self, uuid: &Uuid) -> PeerInfoReply {
		block_on(self.app_inner.request_peer_info(uuid)).unwrap()
	}
	pub fn retrieve_payment_address(
		&mut self,
		recipient: &AuxinAddress,
	) -> auxin_protos::PaymentAddress {
		block_on(self.app_inner.retrieve_payment_address(recipient)).unwrap()
	}
	pub fn send_text(&mut self, recipient_phone: &str, message: &str) {
		let message_struct = auxin::message::MessageOut {
			content: auxin::message::MessageContent::default().with_text(message.into()),
		};
		self.send_message(&AuxinAddress::Phone(recipient_phone.into()), message_struct)
	}
	pub fn query_messages(&mut self) -> Vec<String> {
		let mut result = Vec::default();
		let mut receiver = block_on(AuxinReceiver::new(&mut self.app_inner)).unwrap();
		while let Some(msg) = block_on(receiver.next()) {
			if msg.is_ok() {
				let msg_json = serde_json::to_string_pretty(&msg.unwrap()).unwrap();
				result.push(msg_json)
			} else {
				let err = msg.unwrap_err();
				panic!("Error in message receiver: {:?}", &err);
			}
		}
		return result;
	}
}
