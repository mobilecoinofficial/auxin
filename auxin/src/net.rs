// Copyright (c) 2021 MobileCoin Inc.
// Copyright (c) 2021 Emily Cultip

use std::{fmt::Debug, pin::Pin};

use crate::Result;
use futures::Future;

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

#[derive(Debug, Clone)]
///An element in a multipart form HMTL request.
pub enum MultipartEntry {
	Text {
		field_name: String,
		value: String,
	},
	File {
		field_name: String,
		file_name: String,
		file: Vec<u8>,
	},
}

//pub type MultipartRequest = http::request::Request<>;
pub type MultipartForm = Vec<MultipartEntry>;

/// Convenience function to fill in some of the common HTTP headers used by Signal, such as USER_AGENT, X_SIGNAL_AGENT, and Authorization
///
/// # Arguments
///
/// * `verb` - The verb of the HTTP request, such as GET, POST, etc.
/// * `uri` - The web address to which your request will be made.
/// * `auth` - The authorization string. Should match the format produced by make_auth_header(). Fits the format of Base64::encode("username:pasword")
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

/// Represents the response pending from an HTTP request.
pub type ResponseFuture<E> = Pin<
	Box<
		dyn Future<Output = std::result::Result<http::response::Response<Vec<u8>>, E>>
			+ Send
			+ Unpin,
	>,
>;

/// A trait used to wrap an HTTP connection which you can make requests of.
/// "Clone" in this case must clone a reference - much like Arc<T>'s behavior. 
pub trait AuxinHttpsConnection : Clone {
	type Error: 'static + std::error::Error + Send;
	/// Make an HTTPS request.
	fn request(&self, req: Request) -> ResponseFuture<Self::Error>;
	///Make a form / multipart request
	fn multipart_request(
		&self,
		form: MultipartForm,
		req: http::request::Builder,
	) -> ResponseFuture<Self::Error>;
}

/// Wraps a future pending on initating as new connection to HTTPS or Websocket.
pub type ConnectFuture<O, E> =
	Pin<Box<dyn Future<Output = std::result::Result<O, E>> + Send + Unpin>>;

/// The trait used to give an AuxinApp (abstracted from any particular i/o code) the ability to initiate HTTPS and WebSocket connections.
pub trait AuxinNetManager {
	type C: AuxinHttpsConnection + Sized + Send + Clone;

	type Error: 'static + std::error::Error + Send;

	/// Initialize an https connection to Signal which recognizes Signal's self-signed TLS certificate.
	fn connect_to_signal_https(&mut self) -> ConnectFuture<Self::C, Self::Error>;
}
