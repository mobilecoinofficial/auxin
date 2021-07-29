use core::fmt;

use auxin::{LocalIdentity, SIGNAL_TLS_CERT, net::*};
use auxin::Result;

use async_trait::async_trait;
use hyper::client::HttpConnector;
use hyper_tls::{HttpsConnector};
use log::debug;
use tokio_native_tls::native_tls::{TlsConnector, Certificate};


pub fn load_root_tls_cert() -> Result<Certificate> {
	debug!("Loading Signal's self-signed certificate.");
	Ok(Certificate::from_pem(SIGNAL_TLS_CERT.as_bytes())?)
}

async fn build_tls_connector(cert: Certificate) -> Result<tokio_native_tls::TlsConnector> {
	let mut builder = TlsConnector::builder();
	// Recognize SIGNAL_SELF_SIGNED_CERT but do not accept other invalid certs.
	//let cert = load_root_tls_cert().await?;
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
/*
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
}*/
/*
// (Try to) read a raw byte buffer as a Signal Websocketmessage protobuf.
fn read_wsmessage(buf: &[u8]) -> Result<auxin_protos::WebSocketMessage> {
	let new_buf = fix_protobuf_buf(&Vec::from(buf))?;
	let mut reader = protobuf::CodedInputStream::from_bytes(new_buf.as_slice());
	Ok(reader.read_message()?)
}

///Blocking operation to loop on retrieving a Hyper response's body stream and turn it into an ordinary buffer. 
async fn read_body_stream_to_buf(resp: &mut hyper::Body) -> Result<Vec<u8>> { 
	let mut buf: Vec<u8> = Vec::default();
	while let Some(next) = resp.data().await {
		let chunk = next?;
		let b: &[u8] = chunk.borrow();
		let mut v = Vec::from(b);
		buf.append(&mut v);
	}
	Ok(buf)
}*/

pub struct AuxinHyperConnection { 
    pub client: hyper::Client<HttpsConnector<HttpConnector>, hyper::Body>,
}
impl AuxinHyperConnection { 
    fn body_convert_out(req: http::request::Request<String>) -> http::request::Request<hyper::Body> { 
        let (parts, b) = req.into_parts();
        let body = hyper::Body::from(b);
        http::request::Request::from_parts(parts, body)
    }
    async fn body_convert_in(res: http::Response<hyper::Body>) -> Result<http::response::Response<String>> { 
        let (parts, body) = res.into_parts();
        let bytes = hyper::body::to_bytes(body).await?;
        let string_body = String::from_utf8_lossy(&bytes);
        let resp = http::response::Response::from_parts(parts, string_body.to_string());
        Ok(resp)
    }
}

#[derive(Debug, Clone)]
pub enum SendAttemptError { 
    CannotRequest(String), 
    CannotCompleteResponseBody(String), 
}
impl fmt::Display for SendAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self { 
            Self::CannotRequest(e) => write!(f, "Unable to send an HTTP request: {}", e),
            Self::CannotCompleteResponseBody(e) => write!(f, "Unable to complete a streaming http response body: {}", e),
        }
    }
}

impl std::error::Error for SendAttemptError {}

#[async_trait]
impl AuxinHttpsConnection for AuxinHyperConnection { 
    type Error = SendAttemptError;
	async fn request(&self, req: http::request::Request<String>) -> std::result::Result<http::Response<String>, Self::Error> {
        let res = self.client.request(AuxinHyperConnection::body_convert_out(req)).await
            .map_err(|e| SendAttemptError::CannotRequest(e.to_string()) )?;
        let converted_res = AuxinHyperConnection::body_convert_in(res).await
            .map_err(|e| SendAttemptError::CannotCompleteResponseBody(e.to_string()) )?;
        Ok(converted_res) 
    }
}

pub struct AuxinTungsteniteConnection { 
    //TODO
}

#[async_trait]
impl AuxinWebsocketConnection for AuxinTungsteniteConnection { 
    // TODO for receive. 
}

pub struct NetManager {
    /// Pass in Signal's self-signed certificate.
    cert: Certificate
}

impl NetManager { 
    pub fn new(cert: Certificate) -> Self {
        Self { cert }
    }
}

#[derive(Debug, Clone)]
pub enum EstablishConnectionError { 
    CannotTls(String),
    FailedHttpsConnect(String),
}
impl fmt::Display for EstablishConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self { 
            Self::CannotTls(e) => write!(f, "Failed to construct a TLS connector: {}", e),
            Self::FailedHttpsConnect(e) => write!(f, "Could not construct an HTTPS stream: {}", e),
        }
    }
}

impl std::error::Error for EstablishConnectionError {}

#[async_trait]
impl AuxinNetManager for NetManager { 
	type C = AuxinHyperConnection;
	type W = AuxinTungsteniteConnection;
    type Error = EstablishConnectionError;
	
	/// Initialize an https connection to Signal which recognizes Signal's self-signed TLS certificate. 
	async fn connect_to_signal_https(&mut self) -> std::result::Result<Self::C, Self::Error> {
        //Regular TLS connection (not websocket) for getting a sender cert.
        let connector = build_tls_connector(self.cert.clone()).await
            .map_err(|e| EstablishConnectionError::CannotTls(e.to_string()) )?;
        let mut http_connector = HttpConnector::new();
        //Critically important. If we do not set this value to false, it will defalt to true,
        //and the connector will errror out when we attempt to connect using https://
        //(Because technically it isn't http)
        http_connector.enforce_http(false);
        let https_connector = hyper_tls::HttpsConnector::from((http_connector, connector));

        let client = hyper::Client::builder().build::<_, hyper::Body>(https_connector);
        Ok(AuxinHyperConnection {
            client,
        })
    }

	/// Initialize a websocket connection to Signal's "https://textsecure-service.whispersystems.org" address, taking our credentials as an argument. 
	async fn connect_to_signal_websocket(&mut self, credentials: &LocalIdentity) -> std::result::Result<Self::W, Self::Error> {
        //TODO
        Ok(AuxinTungsteniteConnection{})
    }
}