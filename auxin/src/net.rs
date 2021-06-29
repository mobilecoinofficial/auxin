use crate::{LocalIdentity, Result};

// Required HTTP header for our Signal requests. 
// Authorization: "Basic {AUTH}""
// AUTH is a base64-encoding of: NUMBER:B64PWD, where NUMBER is our phone number and 
// B64PWD is our base64-encoded password.
pub fn make_auth_header(our_credentials: &LocalIdentity) -> String {
	let mut our_auth_value = String::default();
    // We have to supply our own address as a phone number
    // It will not accept this if we use our UUID. 
	our_auth_value.push_str(our_credentials.our_address.address.get_phone_number().unwrap());
	our_auth_value.push_str(":");
	our_auth_value.push_str(&our_credentials.password);


	let b64_auth = base64::encode(our_auth_value);

	let mut our_auth = String::from("Basic ");
	our_auth.push_str(b64_auth.as_str());

	our_auth
}

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

pub fn build_sendercert_request<Body: Default>(local_identity: &LocalIdentity) -> Result<http::Request<Body>> {
	let auth_header = make_auth_header(&local_identity);

	let mut req = http::Request::get("https://textsecure-service.whispersystems.org/v1/certificate/delivery");
	req = req.header("Authorization", auth_header.as_str());
	req = req.header("X-Signal-Agent", X_SIGNAL_AGENT);
	req = req.header("User-Agent", USER_AGENT);

	Ok(req.body(Body::default())?)
}