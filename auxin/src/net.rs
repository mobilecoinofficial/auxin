use crate::{LocalIdentity};


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