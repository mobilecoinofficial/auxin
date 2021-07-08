use crate::Result;

#[allow(unused_must_use)]
pub mod api_paths { 
    pub const API_ROOT : &str = "https://textsecure-service.whispersystems.org";
    pub const SENDER_CERT: &str = "/v1/certificate/delivery";
    pub const MESSAGES: &str = "/v1/messages/";
}

///For "User-Agent" http header
pub const USER_AGENT: &str = "auxin";
///For "X-Signal-Agent" http header
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