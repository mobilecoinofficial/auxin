use std::{fmt::Debug, pin::Pin};

use crate::{LocalIdentity, Result};
use futures::{Sink, Stream, Future};

#[allow(unused_must_use)]
pub mod api_paths {
	pub const API_ROOT: &str = "https://textsecure-service.whispersystems.org";
	pub const SENDER_CERT: &str = "/v1/certificate/delivery";
	pub const MESSAGES: &str = "/v1/messages/";
	pub const SIGNAL_CDN: &str = "https://cdn.signal.org";
	pub const SIGNAL_CDN_2: &str = "https://cdn2.signal.org";
}

//For "User-Agent" http header
pub const USER_AGENT: &str = "auxin";
//For "X-Signal-Agent" http header
pub const X_SIGNAL_AGENT: &str = "auxin";

pub type Body = Vec<u8>;
pub type Request = http::request::Request<Body>;
pub type Response = http::Response<Body>;

///An element in a multipart form HMTL request. 
pub enum MultipartEntry {
	Text{ field_name: String, value: String },
	File{ field_name: String, file_name: String, file: Vec<u8>},
}

pub type MultipartRequest = http::request::Request<Vec<MultipartEntry>>;

pub fn common_http_headers(
	verb: http::Method,
	uri: &str,
	auth: &str,
) -> Result<http::request::Builder> {
	let mut req = http::Request::builder();
	req = req.uri(uri);
	req = req.method(verb);
	req = req.header("Authorization", auth);
	req = req.header("X-Signal-Agent", X_SIGNAL_AGENT);
	req = req.header("User-Agent", USER_AGENT);

	Ok(req)
}

pub type ResponseFuture<E> = Pin<Box<
	dyn Future<
		Output=std::result::Result<http::response::Response<Vec<u8>>, E>
	> + Send + Unpin
>>;

pub trait AuxinHttpsConnection {
	type Error: 'static + std::error::Error + Send;
	fn request(
		&self,
		req: Request,
	) -> ResponseFuture<Self::Error>;
	///Make a form / multipart request
	fn multipart_request(
		&self,
		req: MultipartRequest,
	) -> ResponseFuture<Self::Error>;
}
pub trait AuxinWebsocketConnection {
	type Message: From<auxin_protos::WebSocketMessage>
		+ Into<auxin_protos::WebSocketMessage>
		+ Clone
		+ Debug
		+ Send;
	type SinkError: Debug + std::error::Error;
	type StreamError: Debug + std::error::Error;

	///Converts this type into a message sink and a message stream..
	fn into_streams(
		self,
	) -> (
		Pin<Box<dyn Sink<Self::Message, Error = Self::SinkError>>>,
		Pin<Box<dyn Stream<Item = std::result::Result<Self::Message, Self::StreamError>>>>,
	);
}

pub type ConnectFuture<O, E> = Pin<Box<
	dyn Future<
		Output=std::result::Result<O, E>
	> + Send + Unpin
>>;

pub trait AuxinNetManager {
	type C: AuxinHttpsConnection + Sized + Send + Clone;
	type W: AuxinWebsocketConnection + Sized + Send;

	type Error: 'static + std::error::Error + Send;


	/// Initialize an https connection to Signal which recognizes Signal's self-signed TLS certificate.
	fn connect_to_signal_https(&mut self) -> ConnectFuture<Self::C, Self::Error>;

	/// Initialize a websocket connection to Signal's "https://textsecure-service.whispersystems.org" address, taking our credentials as an argument.
	fn connect_to_signal_websocket(
		&mut self,
		credentials: LocalIdentity,
	) -> ConnectFuture<Self::W, Self::Error>;
}
