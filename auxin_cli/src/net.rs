use core::fmt;
use std::{convert::TryFrom};

use async_global_executor::block_on;
use auxin::{message::fix_protobuf_buf, net::*, LocalIdentity, SIGNAL_TLS_CERT};

use futures::{SinkExt, StreamExt, TryFutureExt};
use hyper::client::HttpConnector;
use hyper_multipart_rfc7578::client::multipart;
use hyper_tls::{HttpsConnector, TlsStream};
use std::io::Cursor;

use log::{debug, trace};
use protobuf::{CodedOutputStream, Message};
use tokio::{
	io::{AsyncRead, AsyncWrite},
	net::TcpStream,
};
use tokio_native_tls::native_tls::{Certificate, TlsConnector};
use tokio_tungstenite::WebSocketStream;

use auxin_protos::{
	WebSocketMessage, WebSocketMessage_Type, WebSocketRequestMessage, WebSocketResponseMessage,
};
use rand::{RngCore, rngs::OsRng};

use auxin::{ReceiveError, net::{AuxinNetManager}};

pub fn load_root_tls_cert() -> std::result::Result<Certificate, EstablishConnectionError> {
	trace!("Loading Signal's self-signed certificate.");
	Certificate::from_pem(SIGNAL_TLS_CERT.as_bytes())
		.map_err(|e| EstablishConnectionError::TlsCertFailure(format!("{:?}", e)))
}

async fn build_tls_connector(
	cert: Certificate,
) -> std::result::Result<tokio_native_tls::TlsConnector, EstablishConnectionError> {
	let mut builder = TlsConnector::builder();
	// Recognize SIGNAL_SELF_SIGNED_CERT but do not accept other invalid certs.
	builder.add_root_certificate(cert);

	let connector: tokio_native_tls::native_tls::TlsConnector = builder
		.build()
		.map_err(|e| EstablishConnectionError::CannotTls(format!("{:?}", e)))?;
	Ok(tokio_native_tls::TlsConnector::from(connector))
}

async fn connect_tls_for_websocket(
	cert: Certificate,
) -> std::result::Result<TlsStream<TcpStream>, EstablishConnectionError> {
	let first_future = build_tls_connector(cert);
	let second_future = TcpStream::connect("textsecure-service.whispersystems.org:443")
		.map_err(|e| EstablishConnectionError::CannotTls(format!("{:?}", e)));
	let (connector, stream) = tokio::try_join!(first_future, second_future)?;

	connector
		.connect("textsecure-service.whispersystems.org", stream)
		.await
		.map_err(|e| EstablishConnectionError::CannotTls(format!("{:?}", e)))
}

// Signal's API lives at textsecure-service.whispersystems.org.
async fn connect_websocket<S: AsyncRead + AsyncWrite + Unpin>(
	local_identity: &LocalIdentity,
	stream: S,
) -> std::result::Result<
	(WebSocketStream<S>, tungstenite::http::Response<()>),
	EstablishConnectionError,
> {
	let signal_url = "https://textsecure-service.whispersystems.org";

	// Make a websocket URI which has the right protocol.
	let ws_uri = signal_url
		.replace("https://", "wss://")
		.replace("http://", "ws://")
		+ "/v1/websocket/";

	// API arguments to identify ourselves.
	let mut filled_uri = ws_uri.clone();
	filled_uri.push_str("?login=");
	filled_uri.push_str(
		local_identity
			.address
			.get_uuid()
			.unwrap()
			.to_string()
			.as_str(),
	);
	filled_uri.push_str(format!(".{}", local_identity.address.device_id).as_str()); // Device ID
	filled_uri.push_str("&password=");
	filled_uri.push_str(&local_identity.password);

	let auth_header = local_identity.make_auth_header();

	let headers = &mut [
		httparse::Header {
			name: "Authorization",
			value: auth_header.as_bytes(),
		},
		httparse::Header {
			name: "X-Signal-Agent",
			value: "auxin".as_bytes(),
		},
	];
	let req = httparse::Request {
		method: Some("GET"),
		path: Some(filled_uri.as_str()),
		version: Some(11),
		headers,
	};

	trace!("Connecting to websocket with request {:?}", req);
	tokio_tungstenite::client_async(req, stream)
		.await
		.map_err(|e| EstablishConnectionError::CantStartWebsocketConnect(format!("{:?}", e)))
}

// (Try to) read a raw byte buffer as a Signal Websocketmessage protobuf.
fn read_wsmessage(
	buf: &[u8],
) -> std::result::Result<auxin_protos::WebSocketMessage, WebsocketError> {
	let new_buf = fix_protobuf_buf(&Vec::from(buf))
		.map_err(|e| WebsocketError::FailedtoDeserialize(format!("{:?}", e)))?;
	let mut reader = protobuf::CodedInputStream::from_bytes(new_buf.as_slice());
	reader
		.read_message()
		.map_err(|e| WebsocketError::FailedtoDeserialize(format!("{:?}", e)))
}

#[derive(Clone)]
pub struct AuxinHyperConnection {
	pub client: hyper::Client<HttpsConnector<HttpConnector>, hyper::Body>,
}

#[derive(Debug, Clone)]
pub enum SendAttemptError {
	CannotRequest(String),
	CannotCompleteResponseBody(String),
	CannotBuildMultipartRequest(String),
}
impl fmt::Display for SendAttemptError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match &self {
			Self::CannotRequest(e) => write!(f, "Unable to send an HTTP request: {}", e),
			Self::CannotCompleteResponseBody(e) => write!(
				f,
				"Unable to complete a streaming http response body: {}",
				e
			),
			Self::CannotBuildMultipartRequest(e) => {
				write!(f, "Could not construct a multipart request: {}", e)
			}
		}
	}
}

impl std::error::Error for SendAttemptError {}

#[derive(Debug)]
pub enum WebsocketError {
	FailedtoDeserialize(String),
	UnderlyingMessageReceive(String),
	TungsteniteError(tungstenite::Error),
	StreamClosed(Option<tungstenite::protocol::CloseFrame<'static>>),
}
impl fmt::Display for WebsocketError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match &self {
			Self::FailedtoDeserialize(e) => write!(f, "Could not deserialize to a \"Websocket Message\" protobuf: {}", e),
			Self::UnderlyingMessageReceive(e) => write!(f, "The library Auxin uses for WebSocket connections, Tungstenite, caught an error on polling for new messages: {}", e),
			Self::TungsteniteError(e) => write!(f, "{:?}", e),
			Self::StreamClosed(e) => {
				match e {
					Some(frame) => write!(f, "Stream was closed - reason: {:?}", frame),
					None => write!(f, "Stream was closed with no close frame."),
				}
			},
		}
	}
}

impl std::error::Error for WebsocketError {}

impl AuxinHttpsConnection for AuxinHyperConnection {
	type Error = SendAttemptError;

	fn request(&self, req: http::request::Request<Vec<u8>>) -> ResponseFuture<Self::Error> {
		let (parts, b) = req.into_parts();
		let body = hyper::Body::from(b);

		let fut = self
			.client
			.request(http::request::Request::from_parts(parts, body))
			.map_err(|e| SendAttemptError::CannotRequest(e.to_string()))
			.map_ok(move |res| {
				let (parts, body) = res.into_parts();
				Box::pin(hyper::body::to_bytes(body))
					.map_ok(move |bytes| {
						http::response::Response::from_parts(parts, bytes.to_vec())
					})
					.map_err(|e| SendAttemptError::CannotCompleteResponseBody(e.to_string()))
			})
			.try_flatten();
		Box::pin(fut)
	}

	fn multipart_request(
		&self,
		form: MultipartForm,
		req: http::request::Builder,
	) -> ResponseFuture<Self::Error> {
		let form = form;
		let mut hyper_form = multipart::Form::default();
		for entry in form.iter() {
			match entry {
				MultipartEntry::Text { field_name, value } => {
					hyper_form.add_text(field_name.clone(), value.clone());
				}
				MultipartEntry::File {
					field_name,
					file_name,
					file,
				} => {
					let cursor = Cursor::new(file.clone());
					hyper_form.add_reader_file(field_name.clone(), cursor, file_name.clone());
				}
			}
		}

		//let request = hyper_form.set_body_convert::<hyper::Body, multipart::Body>(req).unwrap();
		let request = hyper_form
			.set_body_convert::<hyper::Body, multipart::Body>(req)
			.unwrap();
		let (mut parts, body) = request.into_parts();

		let bytes: Vec<u8> = block_on(hyper::body::to_bytes(body))
			.unwrap()
			.into_iter()
			.collect();

		let size = bytes.len();

		//let mut fixed_request: http::Request<Vec<u8>> = http::Request::from_parts(parts, bytes);

		parts
			.headers
			.insert("Content-Length", http::HeaderValue::from(size));

		let request: hyper::Request<hyper::Body> =
			hyper::Request::from_parts(parts, hyper::Body::try_from(bytes).unwrap());

		let fut = self
			.client
			.request(request)
			.map_err(|e| SendAttemptError::CannotBuildMultipartRequest(format!("{:?}", e)))
			.map_ok(move |res| {
				let (parts, body) = res.into_parts();
				Box::pin(hyper::body::to_bytes(body))
					.map_ok(move |bytes| {
						http::response::Response::from_parts(parts, bytes.to_vec())
					})
					.map_err(|e| SendAttemptError::CannotCompleteResponseBody(e.to_string()))
			})
			.try_flatten();
		Box::pin(fut)
	}
}

pub type WsStream = WebSocketStream<TlsStream<TcpStream>>;

pub struct AuxinTungsteniteConnection {
	credentials: LocalIdentity,
	client: WsStream,
}

pub struct NetManager {
	/// Pass in Signal's self-signed certificate.
	cert: Certificate,
}

impl NetManager {
	pub fn new(cert: Certificate) -> Self {
		Self { cert }
	}
}

#[derive(Debug, Clone)]
pub enum EstablishConnectionError {
	CannotTls(String),
	TlsCertFailure(String),
	FailedHttpsConnect(String),
	CantStartWebsocketConnect(String),
	BadUpgradeResponse(String),
}
impl fmt::Display for EstablishConnectionError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match &self {
			Self::CannotTls(e) => write!(f, "Failed to construct a TLS connector: {}", e),
			Self::TlsCertFailure(e) => write!(
				f,
				"Could not initialize the root Signal web API self-signed certificate: {}",
				e
			),
			Self::FailedHttpsConnect(e) => write!(f, "Could not construct an HTTPS stream: {}", e),
			Self::CantStartWebsocketConnect(e) => {
				write!(f, "Could not initiate a websocket connection: {}", e)
			}
			Self::BadUpgradeResponse(e) => write!(
				f,
				"Failed to connect as Websocket client, got response: {}",
				e
			),
		}
	}
}
impl std::error::Error for EstablishConnectionError {}

impl AuxinNetManager for NetManager {
	type C = AuxinHyperConnection;
	type Error = EstablishConnectionError;

	/// Initialize an https connection to Signal which recognizes Signal's self-signed TLS certificate.
	fn connect_to_signal_https(&mut self) -> ConnectFuture<Self::C, Self::Error> {
		//Regular TLS connection (not websocket) for getting a sender cert.
		let fut = Box::pin(build_tls_connector(self.cert.clone()))
			.map_err(|e| EstablishConnectionError::CannotTls(e.to_string()))
			.map_ok(|tls_connector| {
				let mut http_connector = HttpConnector::new();
				//Critically important. If we do not set this value to false, it will defalt to true,
				//and the connector will errror out when we attempt to connect using https://
				//(Because technically it isn't http)
				http_connector.enforce_http(false);
				let https_connector =
					hyper_tls::HttpsConnector::from((http_connector, tls_connector));

				let client = hyper::Client::builder().build::<_, hyper::Body>(https_connector);
				AuxinHyperConnection { client }
			});
		Box::pin(fut)
	}
}

impl AuxinTungsteniteConnection {
	pub async fn connect(credentials: &LocalIdentity) -> std::result::Result<WsStream, EstablishConnectionError> {
		let cert = load_root_tls_cert()?;
		let tls_stream = connect_tls_for_websocket(cert).await?;
		let (websocket_client, connect_response) = connect_websocket(credentials, tls_stream).await?;
		//It's successful... or is it?
		// Check to make sure our status code is success.
		if !((connect_response.status().as_u16() == 200)
			|| (connect_response.status().as_u16() == 101))
		{
			let r = connect_response.status().as_u16();
			let s = connect_response.status().to_string();
			let err = format!("Status {}: {}", r, s);
			Err(EstablishConnectionError::BadUpgradeResponse(err))
		} else {
			//If it's successful, pass along our value.
			debug!(
				"Constructed websocket client streans, got response: {:?}",
				connect_response
			);

			Ok(websocket_client)
		}
	}

	/// Construct an AuxinReceiver, connecting to Signal's Websocket server.
	///
	/// # Arguments
	///
	/// * `credentials` - The user identity from which we will be connecting to websocket.
	pub async fn new(credentials: LocalIdentity) -> std::result::Result<Self, EstablishConnectionError> {

		let client = Self::connect(&credentials).await?;
		Ok(AuxinTungsteniteConnection {
			credentials,
			client,
		})
	}

	pub async fn send_message(&mut self, msg: auxin_protos::WebSocketMessage) -> std::result::Result<(), tungstenite::Error> { 
		let mut buf: Vec<u8> = Vec::default();
		let mut out_gen = CodedOutputStream::new(&mut buf);
		let _ = msg.compute_size();
		msg.write_to_with_cached_sizes(&mut out_gen).expect("Could not write websocket message.");
		out_gen.flush().expect("Could not write websocket message.");
		drop(out_gen);
		let msg = tungstenite::Message::Binary(buf);

		self.client
			.send(msg)
			.await
	}

	/// Notify the server that we have received a message.
	/// 
	/// Note that thsi only sends the WebSocket acknowledgement. 
	/// AuxinApp::receive_and_acknowledge() sends the Signal protocol "receipt" message. 
	///
	/// # Arguments
	///
	/// * `req` - The original WebSocketRequestMessage - passed so that we can acknowledge that we've received this message even if no valid message can be parsed from it.
	async fn acknowledge_message(
		&mut self,
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

		self.send_message(res_m).await
			.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;

		self.client
			.flush()
			.await
			.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;
		Ok(())
	}

	/// Polls for the next available message.  Returns none when the end of the stream has been reached.
	pub async fn next(&mut self) -> Option<std::result::Result<WebSocketMessage, ReceiveError>> {
		//Try up to 64 times if necessary.
		for _ in 0..64 {
			//Decode to auxin_protos::WebSocketMessage.
			let msg = match self.client.next().await {
				None => None,
				Some(Ok(tungstenite::Message::Text(_msg))) => todo!(), // From json maybe?
				Some(Ok(tungstenite::Message::Binary(buf))) => {
					Some(
						Ok(
							match read_wsmessage(&buf) {
								Ok(msg) => msg, 
								Err(e) => return Some(Err(ReceiveError::DeserializeErr(format!("{:?}", e)))), 
							}
						)
					)
				},
				Some(Ok(tungstenite::Message::Ping(_))) => None,
				Some(Ok(tungstenite::Message::Pong(_))) => None,
				Some(Ok(tungstenite::Message::Close(frame))) => {
					Some(Err(WebsocketError::StreamClosed(frame)))
				},
				_ => None,
			};

			//Match message.
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
									.acknowledge_message(&req)
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
					else { 
						return Some(Ok(wsmessage));
					}
				}
			}
		}
		None
	}

	/// Request additional messages (to continue polling for messages after "/api/v1/queue/empty" has been sent). This is a GET request with path GET /v1/messages/
	pub async fn refresh(&mut self) -> std::result::Result<(), ReceiveError> {
		let mut req = WebSocketRequestMessage::default();

		let mut rng = OsRng::default();
		// Only invocation of "self.app" in this method. Replace? 
		req.set_id(rng.next_u64());
		req.set_verb("GET".to_string());
		req.set_path("/v1/messages/".to_string());
		let mut req_m = WebSocketMessage::default();
		req_m.set_request(req);
		req_m.set_field_type(WebSocketMessage_Type::REQUEST);

		self.send_message(req_m)
			.await
			.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;

		self.client
			.flush()
			.await
			.map_err(|e| ReceiveError::SendErr(format!("{:?}", e)))?;

		Ok(())
	}

	/// Re-initialize a Signal websocket connection so you can continue polling for messages.
	pub async fn reconnect(&mut self) -> crate::Result<()> {
		self.client
			.close(None)
			.await
			.map_err(|e| ReceiveError::ReconnectErr(format!("Could not close: {:?}", e)))?;
		// Better way to do this... 
		let client = Self::connect(&self.credentials)
			.await?;

		self.client = client;

		Ok(())
	}
}