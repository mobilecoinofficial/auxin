use std::borrow::Borrow;
use std::convert::TryFrom;

use auxin::address::AuxinAddress;
use auxin::discovery::{DirectoryAuthResponse, ENCLAVE_ID};
use auxin::message::{AuxinMessageList, MessageContent, MessageIn, MessageOut, fix_protobuf_buf};
use auxin::net::common_http_headers;
use auxin::state::PeerStore;
use auxin::{AuxinConfig, LocalIdentity, generate_timestamp};
use auxin::{Result};
use auxin_protos::WebSocketMessage_Type;
use futures::{StreamExt, TryFutureExt};
use hyper::body::HttpBody;
use hyper::client::HttpConnector;
use hyper_tls::TlsStream;
use log::{LevelFilter, debug, info};
use rand::rngs::OsRng;
use serde_json::json;
use simple_logger::SimpleLogger;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::{WebSocketStream, client_async};
use tungstenite::error::ProtocolError;
use tungstenite::http::Response;
use std::fs;
use tokio_native_tls::native_tls::Certificate;
use tokio_native_tls::native_tls::TlsConnector;

use clap::{App, Arg, SubCommand};

pub mod state;

use crate::state::*;

pub type Context = auxin::AuxinContext<OsRng>;

// TODO: Refactor net stuff here.

async fn load_root_tls_cert() -> Result<Certificate> {
	let key_string = fs::read_to_string("data/whisper.store.asn1")?;
	debug!("Loading Signal's self-signed certificate.");
	Ok(Certificate::from_pem(key_string.as_bytes())?)
}

async fn build_tls_connector() -> Result<tokio_native_tls::TlsConnector> {
	let mut builder = TlsConnector::builder();
	// Recognize SIGNAL_SELF_SIGNED_CERT but do not accept other invalid certs.
	let cert = load_root_tls_cert().await?;
	builder.add_root_certificate(cert);

	let connector: tokio_native_tls::native_tls::TlsConnector = builder.build()?;
	Ok(tokio_native_tls::TlsConnector::from(connector))
}


async fn connect_tls() -> Result<TlsStream<TcpStream> > {

	let (connector, stream) = tokio::try_join!(
		build_tls_connector(),
		TcpStream::connect("textsecure-service.whispersystems.org:443").map_err(|e| Box::new(e))
	)?;

	Ok(connector.connect("textsecure-service.whispersystems.org", stream).await?)
}

// Signal's API lives at textsecure-service.whispersystems.org.
async fn connect_websocket<S: AsyncRead + AsyncWrite + Unpin>(local_identity: &LocalIdentity, stream: S) 
		-> Result<(WebSocketStream<S>, Response<()>)> {
	let signal_url = "https://textsecure-service.whispersystems.org";

	// Make a websocket URI which has the right protocol.
	let ws_uri = signal_url
		.replace("https://", "wss://")
		.replace("http://", "ws://")
		+ "/v1/websocket/";

	// API arguments to identify ourselves.
	let mut filled_uri = ws_uri.clone();
	filled_uri.push_str("?login=");
	filled_uri.push_str(local_identity.our_address.get_uuid()?.to_string().as_str());
	filled_uri.push_str("&password=");
	filled_uri.push_str(&local_identity.password);

	let auth_header = local_identity.make_auth_header();

	let headers = &mut [
		httparse::Header {
			name: "Authorization", 
			value: auth_header.as_bytes()
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
		headers };

	debug!("Connecting to websocket with request {:?}", req);
	Ok(client_async(req, stream).await?)
}

// (Try to) read a raw byte buffer as a Signal Websocketmessage protobuf.
fn read_wsmessage(buf: &[u8]) -> Result<auxin_protos::WebSocketMessage> {
	let new_buf = fix_protobuf_buf(&Vec::from(buf))?;
	let mut reader = protobuf::CodedInputStream::from_bytes(new_buf.as_slice());
	Ok(reader.read_message()?)
}

///Blocking operation to loop on retrieving a Hyper response's body stream and turn it into an ordinary buffer. 
async fn read_body_stream_to_buf(resp: &mut hyper::Response<hyper::Body>) -> Result<Vec<u8>> { 
	let mut buf: Vec<u8> = Vec::default();
	while let Some(next) = resp.data().await {
		let chunk = next?;
		let b: &[u8] = chunk.borrow();
		let mut v = Vec::from(b);
		buf.append(&mut v);
	}
	Ok(buf)
}

#[tokio::main]
pub async fn main() -> Result<()> {
	SimpleLogger::new()
		.with_level(LevelFilter::Debug)
		.init()
		.unwrap();

	const AUTHOR_STR: &str = "Millie C. <gyrocoder@gmail.com>";
	const VERSION_STR: &str = "PRE-RELEASE DO NOT USE";

	let args = App::new("auxin-cli")
						.version(VERSION_STR)
						.author(AUTHOR_STR)
						.about("[TODO]")
						.arg(Arg::with_name("USER")
							.short("u")
							.long("user")
							.value_name("PHONE_NUMBER")
							.required(true)
							.takes_value(true)
							.help("Select username (phone number) from which to use auxin-cli"))
						.subcommand(SubCommand::with_name("send")
							.about("Sends a message to the specified address.")
							.version(VERSION_STR)
							.author(AUTHOR_STR)
							.args_from_usage("<DESTINATION> 'Sets the destination for our message'")
							.arg(Arg::with_name("MESSAGE")
								.short("m")
								.long("message")
								.value_name("MESSAGE_BODY")
								.required(true)
								.takes_value(true)
								.help("Determines the message text we will send."))
						).subcommand(SubCommand::with_name("receive")
							.about("Polls for incoming messages.")
							.version(VERSION_STR)
							.author(AUTHOR_STR))
						.get_matches();

	let our_phone_number = args.value_of("USER").unwrap();
	let our_phone_number = our_phone_number.to_string();

	let trust_root = auxin::sealed_sender_trust_root();

    let base_dir = "state/data/";
    let user_json = load_signal_cli_user(base_dir, &our_phone_number)?;
    let local_identity = local_identity_from_json(&user_json)?;

	println!("Successfully loaded an identity structure for user {}", our_phone_number);

	//Regular TLS connection (not websocket) for getting a sender cert.
	let connector = build_tls_connector().await?;
	let mut http_connector = HttpConnector::new();
	//Critically important. If we do not set this value to false, it will defalt to true,
	//and the connector will errror out when we attempt to connect using https://
	//(Because technically it isn't http)
	http_connector.enforce_http(false);
	let https_connector = hyper_tls::HttpsConnector::from((http_connector, connector));

	let client = hyper::Client::builder().build::<_, hyper::Body>(https_connector);
	let sender_cert_request: http::Request<hyper::Body> = local_identity.build_sendercert_request()?;
	let mut sender_cert_response = client.request(sender_cert_request).await?;

	assert!(sender_cert_response.status().is_success());
	let buf: Vec<u8> = read_body_stream_to_buf(&mut sender_cert_response).await?;

	let cert_structure_string = String::from_utf8_lossy(buf.as_slice());
	let cert_structure : serde_json::Value = serde_json::from_str(&cert_structure_string)?;
	let encoded_cert_str = cert_structure.get("certificate").unwrap();
	let temp_vec = base64::decode(encoded_cert_str.as_str().unwrap())?;

	let sender_cert = libsignal_protocol::SenderCertificate::deserialize(temp_vec.as_slice())?;

	if sender_cert.validate(&trust_root, generate_timestamp() as u64)? { 
		println!("Confirmed our sender certificate is valid!");
	} else {
		panic!("Invalid sender certificate!");
	}

	let mut context: Context = state::make_context(base_dir, local_identity.clone(), sender_cert, AuxinConfig{}, libsignal_protocol::Context::default()).await?;


	//Get upgraded auth for discovery / directory.
	let auth = context.our_identity.make_auth_header();
	let req = common_http_headers(http::Method::GET, 
		"https://textsecure-service.whispersystems.org/v1/directory/auth",
		auth.as_str())?;
	let req = req.body(hyper::Body::default())?;

	let mut auth_upgrade_response = client.request(req).await?;
	assert!(auth_upgrade_response.status().is_success());
	let buf: Vec<u8> = read_body_stream_to_buf(&mut auth_upgrade_response).await?;
	let upgraded_auth_json_str = String::from_utf8_lossy(buf.as_slice());
	debug!("Upgraded authorization response: {}", upgraded_auth_json_str);
	let upgraded_auth : DirectoryAuthResponse = serde_json::from_str(&*upgraded_auth_json_str)?;
	let mut upgraded_auth_token = upgraded_auth.username.clone();
	upgraded_auth_token.push_str(":");
	upgraded_auth_token.push_str(&upgraded_auth.password);
	upgraded_auth_token = base64::encode(upgraded_auth_token);
	debug!("Upgraded authorization token: {}", upgraded_auth_token);
	let mut upgraded_auth_header = String::from("Basic ");
	upgraded_auth_header.push_str(&upgraded_auth_token);
	debug!("Upgraded authorization header: {}", upgraded_auth_header);

	//Temporary Keypair for discovery
	let attestation_path = format!("https://api.directory.signal.org/v1/attestation/{}", ENCLAVE_ID);
	let attestation_keys = libsignal_protocol::KeyPair::generate(&mut context.rng);
	let attestation_request= json!({
		"clientPublic": base64::encode(attestation_keys.public_key.public_key_bytes()?),
	});
	let mut req = common_http_headers(http::Method::PUT, 
		&attestation_path,
		upgraded_auth_header.as_str())?;
	let attestation_request = attestation_request.to_string();
	req = req.header("Content-Type", "application/json; charset=utf-8");
	req = req.header("Content-Length", attestation_request.len());
	let req = req.body(hyper::Body::try_from(attestation_request)?)?;

	debug!("Sending attestation request: {:?}", req);

	let mut attestation_response = client.request(req).await?;
	let buf: Vec<u8> = read_body_stream_to_buf(&mut attestation_response).await?;

	debug!("Attestation response: {:?};  {}", attestation_response, String::from_utf8_lossy(buf.as_slice()));

	if let Some(send_command) = args.subcommand_matches("send") { 
		let dest = send_command.value_of("DESTINATION").unwrap();
		let recipient_addr = AuxinAddress::try_from(dest)?;
		let recipient_addr = context.peer_cache.complete_address(&recipient_addr).unwrap();
		let recipient = context.peer_cache.get(&recipient_addr);
		if let Some(_recipient) = recipient {
			let message_text = send_command.value_of("MESSAGE").unwrap();
			let message_content = MessageContent::TextMessage(message_text.to_string());
			let message = MessageOut {
				content: message_content,
			};

			let message_list = AuxinMessageList {
				messages: vec![message],
				remote_address: recipient_addr.clone(),
			};
			let outgoing_push_list = message_list.generate_sealed_messages_to_all_devices(&mut context, generate_timestamp()).await?;

			let request = outgoing_push_list.build_http_request(&recipient_addr, &mut context)?;
			debug!("Attempting to send message: {:?}", request);
			let mut message_response = client.request(request).await?;
		
			println!("Got response to attempt to send message: {:?}", message_response);
			let buf: Vec<u8> = read_body_stream_to_buf(&mut message_response).await?;
			let reply_string = String::from_utf8_lossy(buf.as_slice());
			println!("Response body is: {:?}", reply_string);

		} else { 
			panic!("Currently this application cannot send to unfamiliar peers. Please send a message to this peer via signal-cli first.");
		}
	}

	
	if let Some(_) = args.subcommand_matches("receive") { 
		let second_stream = connect_tls().await?; 
		let (mut websocket_client, connect_response) = connect_websocket(&local_identity, second_stream).await?;
		debug!("Constructed websocket client, got response: {:?}", connect_response);
	
		let mut count = 0;
		while let Some(msg) = websocket_client.next().await {
			let msg = match msg {
				Ok(m) => m,
				Err(e ) => {
					match e { 
						tungstenite::Error::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
							debug!("Reset without closing handshake - we're probably at the end of the incoming messages list with {} messages.", count);
							break;
						}, 
						_ => {break;},//panic!("Encountered error in websocket polling loop: {}", e),
					}
				},
			};
			match &msg {
				tungstenite::Message::Binary(bin) => {
	
					println!("\n-----------------------------------------\n");
					//The server DEFINITELY has more messages to send us upon connect every time I message this nubmer.
					count += 1;
					println!("-----We have recieved {} messages in total.", count);
					//Decode websocket message
					let wsmessage: auxin_protos::WebSocketMessage = read_wsmessage(bin.as_slice())?;
	
					match wsmessage.get_field_type() {
						WebSocketMessage_Type::REQUEST => {
							
							let req = wsmessage.get_request(); 
	
							println!("\n-----------------------------------------");
							println!("-----------------------------------------\n");
							debug!("Request message: {:?}", req);
							println!("\n-----------------------------------------");
							println!("-----------------------------------------\n");
	
							println!("Message ID: {}", req.get_id());
							println!("Message path: {}", req.get_path());

							if req.get_path().eq_ignore_ascii_case("/api/v1/queue/empty") { 
								info!("Message queue empty, no more messages to receive.");
								break;
							}

							let m = MessageIn::decode_envelope_bin(req.get_body(), &mut context).await?;
							println!("{:?}", m);
						},
						WebSocketMessage_Type::RESPONSE => {
							//let res = wsmessage.get_response();
							//let e : Envelope = read_envelope(res.get_body())?;
	
							//debug!("Decoded websocket response: {:?}", e);
						},
						_ => {},
					}
				},
				tungstenite::Message::Close(_) => {
					break;
				},
				_ => {
	
					println!("\n-----------------------------------------");
					println!("-----------------------------------------\n");
					let msg = match msg.to_text() {
						Ok(inner) => String::from(inner),
						Err(e) => format!("Message decoding errored, with error message \"{}\"", e),
					};
					debug!("Message contents: {}", msg);
				}
			}
		}
	}

	save_all(&context, base_dir).await?;
    Ok(())
}