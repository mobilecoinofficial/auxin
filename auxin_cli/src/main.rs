use std::borrow::Borrow;
use std::convert::TryFrom;

use auxin::address::AuxinAddress;
use auxin::message::{AuxinMessageList, MessageOut, MessageContent};
use auxin::net::{build_sendercert_request};
use auxin::state::PeerStore;
use auxin::{AuxinConfig, generate_timestamp};
use auxin::{Result};
use hyper::body::HttpBody;
use hyper::client::HttpConnector;
use log::{LevelFilter, debug};
use rand::rngs::OsRng;
use simple_logger::SimpleLogger;
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

/*
async fn connect_tls() -> Result<TlsStream<TcpStream> > {

	let (connector, stream) = tokio::try_join!(
		build_tls_connector(),
		TcpStream::connect("textsecure-service.whispersystems.org:443").map_err(|e| Box::new(e))
	)?;

	Ok(connector.connect("textsecure-service.whispersystems.org", stream).await?)
}*/

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
								.help("Determines the message text we will send.")
						))
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
	let sender_cert_request: http::Request<hyper::Body> = build_sendercert_request(&local_identity)?;
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

	let mut context: Context = state::make_context(base_dir, local_identity, sender_cert, AuxinConfig{}, libsignal_protocol::Context::default()).await?;
    println!("Hello, world! This doesn't do much yet.");

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

	save_all(&context, base_dir).await?;
    Ok(())
}