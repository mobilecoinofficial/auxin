use std::{fmt::Debug, pin::Pin};

use crate::{LocalIdentity, Result};
use async_trait::async_trait;
use futures::{Sink, Stream};

#[allow(unused_must_use)]
pub mod api_paths { 
    pub const API_ROOT : &str = "https://textsecure-service.whispersystems.org";
    pub const SENDER_CERT: &str = "/v1/certificate/delivery";
    pub const MESSAGES: &str = "/v1/messages/";
}

//For "User-Agent" http header
pub const USER_AGENT: &str = "auxin";
//For "X-Signal-Agent" http header
pub const X_SIGNAL_AGENT: &str = "auxin";

pub fn common_http_headers(verb: http::Method, uri: &str, auth: &str) -> Result<http::request::Builder> {
	let mut req = http::Request::builder();
	req = req.uri(uri);
	req = req.method(verb);
	req = req.header("Authorization", auth);
	req = req.header("X-Signal-Agent", X_SIGNAL_AGENT);
	req = req.header("User-Agent", USER_AGENT);

	Ok(req)
}

#[async_trait]
pub trait AuxinHttpsConnection { 
	type Error: 'static + std::error::Error + Send;
	async fn request(&self, req: http::request::Request<String>) -> std::result::Result<http::Response<String>, Self::Error>;
}
pub trait AuxinWebsocketConnection { 
	type Message: From<auxin_protos::WebSocketMessage> + Into<auxin_protos::WebSocketMessage> + Clone + Debug + Send;
	type SinkError: Debug + std::error::Error;
	type StreamError: Debug + std::error::Error;

	///Converts this type into a message sink and a message stream..
	fn into_streams(self) -> (Pin<Box<dyn Sink<Self::Message, Error=Self::SinkError>>>, Pin<Box<dyn Stream<Item = std::result::Result<Self::Message, Self::StreamError>>>>);
}

#[async_trait]
pub trait AuxinNetManager { 
	type C: AuxinHttpsConnection;
	type W: AuxinWebsocketConnection;

	type Error: 'static + std::error::Error + Send;
	
	/// Initialize an https connection to Signal which recognizes Signal's self-signed TLS certificate. 
	async fn connect_to_signal_https(&mut self) -> std::result::Result<Self::C, Self::Error>;

	/// Initialize a websocket connection to Signal's "https://textsecure-service.whispersystems.org" address, taking our credentials as an argument. 
	async fn connect_to_signal_websocket(&mut self, credentials: &LocalIdentity) -> std::result::Result<Self::W, Self::Error>;
}