use auxin_protos::{
	WebSocketMessage, WebSocketMessage_Type, WebSocketRequestMessage, WebSocketResponseMessage,
};
use futures::{Sink, SinkExt, Stream, StreamExt};
use log::{debug, info, warn};
use rand::{CryptoRng, RngCore};
use std::pin::Pin;

use crate::{AuxinApp, HandleEnvelopeError, ReceiveError, SendMessageError, address::AuxinAddress, message::{MessageIn, MessageInError, MessageOut}, net::{AuxinNetManager, AuxinWebsocketConnection}, read_envelope_from_bin, state::AuxinStateManager};


type OutstreamT<N> = Pin<
	Box<
		dyn Sink<
			<<N as AuxinNetManager>::W as AuxinWebsocketConnection>::Message,
			Error = <<N as AuxinNetManager>::W as AuxinWebsocketConnection>::SinkError,
		>,
	>,
>;
type InstreamT<N> = Pin<
	Box<
		dyn Stream<
			Item = std::result::Result<
				<<N as AuxinNetManager>::W as AuxinWebsocketConnection>::Message,
				<<N as AuxinNetManager>::W as AuxinWebsocketConnection>::StreamError,
			>,
		>,
	>,
>;

/// A receiver-handle, used to poll an AuxinApp for new incoming messages.
pub struct AuxinReceiver<'a, R, N, S>
where
	R: RngCore + CryptoRng,
	N: AuxinNetManager,
	S: AuxinStateManager,
{
	/// A mutable reference to our AuxinApp.
	pub(crate) app: &'a mut AuxinApp<R, N, S>,
	/// Outgoing message stream (a Rust Futures sink)
	pub(crate) outstream: OutstreamT<N>,
	/// Incoming message stream (a Rust Futures stream)
	pub(crate) instream: InstreamT<N>,
}

impl<'a, R, N, S> AuxinReceiver<'a, R, N, S>
where
	R: RngCore + CryptoRng,
	N: AuxinNetManager,
	S: AuxinStateManager,
{
	/// Construct an AuxinReceiver, connecting to Signal's Websocket server.
	///
	/// # Arguments
	///
	/// * `app` - The Auxin App instance tracking state and used to poll for incoming messages.
	pub async fn new(app: &'a mut AuxinApp<R, N, S>) -> crate::Result<AuxinReceiver<'a, R, N, S>> {
		let ws = app
			.net
			.connect_to_signal_websocket(app.context.identity.clone())
			.await?;
		let (outstream, instream) = ws.into_streams();
		Ok(AuxinReceiver {
			app,
			outstream,
			instream,
		})
	}

	/// Notify the server that we have received a message. If it is a non-receipt Signal message, we will send our receipt indicating we got this message.
	///
	/// # Arguments
	///
	/// * `msg` - The message we are acknowledging, if there is any valid messagehere.
	/// * `req` - The original WebSocketRequestMessage - passed so that we can acknowledge that we've received this message even if no valid message can be parsed from it.
	async fn acknowledge_message(
		&mut self,
		msg: &Option<MessageIn>,
		req: &WebSocketRequestMessage,
	) -> std::result::Result<(), ReceiveError> {
		// Sending responses goes here.
		let reply_id = req.get_id();
		let mut res = WebSocketResponseMessage::default();
		res.set_id(reply_id);
		res.set_status(200); // Success
		res.set_message(String::from("OK"));
		res.set_headers(req.get_headers().clone().into());
		let mut res_m = WebSocketMessage::default();
		res_m.set_response(res);
		res_m.set_field_type(WebSocketMessage_Type::RESPONSE);

		self.outstream
			.send(res_m.into())
			.await
			.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;

		if let Some(msg) = msg {
			// Send receipts if we have to.
			if msg.needs_receipt() {
				let receipt = msg.generate_receipt(auxin_protos::ReceiptMessage_Type::DELIVERY);
				self.app
					.send_message(&msg.remote_address.address, receipt)
					.await
					.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;
			}
		}

		self.outstream
			.flush()
			.await
			.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;
		Ok(())
	}

	/// Parse the next message. This is separated from next() to make error handling neater.
	/// If this returns None, that means a certain kind of error has occurred in decryption.
	/// Often there are messages with signatures which have expired, or bad keystate.
	/// The server will continue to re-send these messages to us perpetually unless we acknowledge
	/// them with a receipt.
	/// They will never be possible to decode and that is how the Signal protocol works.
	/// So, it's necessary to treat this as a recoverable error, acknowledge the message, and move on.
	///
	/// # Arguments
	///
	/// * `wsmessage` - The WebsocketMessage we have just received.
	async fn next_inner(
		&mut self,
		wsmessage: &auxin_protos::WebSocketMessage,
	) -> std::result::Result<Option<MessageIn>, ReceiveError> {
		match wsmessage.get_field_type() {
			auxin_protos::WebSocketMessage_Type::UNKNOWN => Err(ReceiveError::UnknownWebsocketTy),
			auxin_protos::WebSocketMessage_Type::REQUEST => {
				let req = wsmessage.get_request();

				let envelope = read_envelope_from_bin(req.get_body())
					.map_err(|e| ReceiveError::DeserializeErr(format!("{:?}", e)))?;

				let maybe_a_message = self.app.handle_inbound_envelope(envelope).await;

				// Done this way to ensure invalid messages are still acknowledged, to clear them from the queue.
				let msg = match maybe_a_message {
					Err(HandleEnvelopeError::MessageDecodingErr(
						MessageInError::ProtocolError(e),
					)) => {
						warn!("Message failed to decrypt - ignoring error and continuing to receive messages to clear out prior bad state. Error was: {:?}", e);
						None
					}
					Err(HandleEnvelopeError::ProtocolErr(e)) => {
						warn!("Message failed to decrypt - ignoring error and continuing to receive messages to clear out prior bad state. Error was: {:?}", e);
						None
					}
					Err(HandleEnvelopeError::MessageDecodingErr(
						MessageInError::DecodingProblem(e),
					)) => {
						warn!("Message failed to decode (bad envelope?) - ignoring error and continuing to receive messages to clear out prior bad state. Error was: {:?}", e);
						None
					}
					Err(e) => {
						return Err(e.into());
					}
					Ok(m) => m,
					//It's okay that this can return None, because next() will continue to poll on a None return from this method, and try getting more messages.
					//"None" returns from handle_inbound_envelope() imply messages meant for the protocol rather than the end-user.
				};

				//This will at least acknowledge to WebSocket that we have received this message.
				self.acknowledge_message(&msg, req).await?;

				if let Some(msg) = &msg {
					//Save session.
					self.app
						.state_manager
						.save_peer_sessions(&msg.remote_address.address, &self.app.context)
						.map_err(|e| ReceiveError::StoreStateError(format!("{:?}", e)))?;
				}
				Ok(msg)
			}
			auxin_protos::WebSocketMessage_Type::RESPONSE => {
				let res = wsmessage.get_response();
				info!("WebSocket response message received: {:?}", res);
				Ok(None)
			}
		}
	}
	/// Polls for the next available message.  Returns none when the end of the stream has been reached.
	/// If next_inner() returns a None, that is interpreted as a recoverable error, and next()
	/// will loop until it encounters a valid message or the end of the list is reached.
	pub async fn next(&mut self) -> Option<std::result::Result<MessageIn, ReceiveError>> {
		//Try up to 64 times if necessary.
		for _ in 0..64 {
			let msg = self.instream.next().await;

			match msg {
				None => {
					return None;
				}
				Some(Err(e)) => {
					return Some(Err(ReceiveError::NetSpecific(format!("{:?}", e))));
				}
				Some(Ok(m)) => {
					let wsmessage: WebSocketMessage = m.into();
					//Check to see if we're done.
					if wsmessage.get_field_type() == WebSocketMessage_Type::REQUEST {
						let req = wsmessage.get_request();
						if req.has_path() {
							// The server has sent us all the messages it has waiting for us.
							if req.get_path().contains("/api/v1/queue/empty") {
								debug!("Received an /api/v1/queue/empty message. Message receiving complete.");
								//Acknowledge we received the end-of-queue and do many clunky error-handling things:
								let res = self
									.acknowledge_message(&None, req)
									.await
									.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)));
								let res = match res {
									Ok(()) => None,
									Err(e) => Some(Err(e)),
								};

								// Receive operation is done. Indicate there are no further messages left to poll for.
								return res; //Usually this returns None.
							}
						}
					}

					//Actually parse our message otherwise.
					match self.next_inner(&wsmessage).await {
						Ok(Some(message)) => return Some(Ok(message)),
						Ok(None) =>
							/*Message failed to decode - ignoring error and continuing to receive messages to clear out prior bad state*/
							{}
						Err(e) => return Some(Err(e)),
					}
				}
			}
		}
		None
	}

	/// Convenience method so we don't have to work around the borrow checker to call send_message on our app when the Receiver has an &mut app.
	///	Simply calls self.app.send_message()
	///
	/// # Arguments
	///
	/// * `recipient_addr` - The address of the peer to whom we're sending a Signal message.
	/// * `message` - The message that we are sending.
	pub async fn send_message(
		&mut self,
		recipient_addr: &AuxinAddress,
		message: MessageOut,
	) -> std::result::Result<crate::Timestamp, SendMessageError> {
		self.app.send_message(recipient_addr, message).await
	}

	/// Request additional messages (to continue polling for messages after "/api/v1/queue/empty" has been sent). This is a GET request with path GET /v1/messages/
	pub async fn refresh(&mut self) -> std::result::Result<(), ReceiveError> {
		let mut req = WebSocketRequestMessage::default();
		// Only invocation of "self.app" in this method. Replace? 
		req.set_id(self.app.rng.next_u64());
		req.set_verb("GET".to_string());
		req.set_path("/v1/messages/".to_string());
		let mut req_m = WebSocketMessage::default();
		req_m.set_request(req);
		req_m.set_field_type(WebSocketMessage_Type::REQUEST);

		self.outstream
			.send(req_m.into())
			.await
			.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;

		self.outstream
			.flush()
			.await
			.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;

		Ok(())
	}

	/// Re-initialize a Signal websocket connection so you can continue polling for messages.
	pub async fn reconnect(&mut self) -> crate::Result<()> {
		self.outstream
			.close()
			.await
			.map_err(|e| ReceiveError::ReconnectErr(format!("Could not close: {:?}", e)))?;
		// Better way to do this... 
		let ws = self
			.app
			.net
			.connect_to_signal_websocket(self.app.context.identity.clone())
			.await?;
		let (outstream, instream) = ws.into_streams();

		self.outstream = outstream;
		self.instream = instream;

		Ok(())
	}

	/// Get a mutable borrow to the AuxinApp this receiver is using.
	pub fn borrow_app(&mut self) -> &mut AuxinApp<R, N, S> {
		self.app
	}
}