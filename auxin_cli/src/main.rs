use std::borrow::Borrow;

use auxin::net::{USER_AGENT, X_SIGNAL_AGENT, make_auth_header};
use auxin::{AuxinConfig, LocalIdentity, generate_timestamp};
use auxin::{Result};
use hyper::Body;
use hyper::body::HttpBody;
use hyper::client::HttpConnector;
use log::debug;
use rand::Rng;
use rand::rngs::OsRng;
use std::fs;
use tokio_native_tls::native_tls::Certificate;
use tokio_native_tls::native_tls::TlsConnector;

use clap::{Arg, App};

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

fn build_sendercert_request<R: Rng>(local_identity: &LocalIdentity, _rng: &mut R) -> Result<hyper::Request<Body>> { 

	let auth_header = make_auth_header(&local_identity);

	let mut req = hyper::Request::get("https://textsecure-service.whispersystems.org/v1/certificate/delivery");
	req = req.header("Authorization", auth_header.as_str());
	req = req.header("X-Signal-Agent", X_SIGNAL_AGENT);
	req = req.header("User-Agent", USER_AGENT);

	Ok(req.body(hyper::Body::default())?)
}

#[tokio::main]
pub async fn main() -> Result<()> {
	let args = App::new("auxin-cli")
						.version("PRE-RELEASE DO NOT USE")
						.author("Millie C. <gyrocoder@gmail.com>")
						.about("[TODO]")
						.arg(Arg::with_name("user")
							.short("u")
							.long("user")
							.value_name("PHONE_NUMBER")
							.required(true)
							.takes_value(true)
							.help("Select username (phone number) from which to use auxin-cli"))
						.get_matches();

	let our_phone_number = args.value_of("user").unwrap();
	let our_phone_number = our_phone_number.to_string();

	let trust_root = auxin::sealed_sender_trust_root();

    let base_dir = "state/data/";
    let user_json = load_signal_cli_user(base_dir, &our_phone_number)?;
    let local_identity = local_identity_from_json(&user_json)?;

	println!("Successfully loaded an identity structure for user {}", our_phone_number);

	let mut csprng = OsRng;

	//Regular TLS connection (not websocket) for getting a sender cert.
	let connector = build_tls_connector().await?;
	let mut http_connector = HttpConnector::new();
	http_connector.enforce_http(false);
	let https_connector = hyper_tls::HttpsConnector::from((http_connector, connector));
	let client = hyper::Client::builder().build::<_, hyper::Body>(https_connector);
	let sender_cert_request = build_sendercert_request(&local_identity, &mut csprng)?;
	let mut sender_cert_response = client.request(sender_cert_request).await?;

	assert!(sender_cert_response.status().is_success());
	let mut buf: Vec<u8> = Vec::default();
	while let Some(next) = sender_cert_response.data().await {
		let chunk = next?;
		let b: &[u8] = chunk.borrow();
		let mut v = Vec::from(b);
		buf.append(&mut v);
	}

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

	let _context: Context = state::make_context(base_dir, local_identity, sender_cert, AuxinConfig{}, libsignal_protocol::Context::default()).await?;
    println!("Hello, world! This doesn't do much yet.");
    Ok(())
}