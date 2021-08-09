use core::fmt;
use std::pin::Pin;

use auxin::message::fix_protobuf_buf;
use auxin::{LocalIdentity, SIGNAL_TLS_CERT, net::*};
use auxin::Result;

use async_trait::async_trait;
use futures::{Sink, SinkExt, Stream, StreamExt, TryFutureExt};
use hyper::client::{HttpConnector};
use hyper_tls::{HttpsConnector};
use log::{debug, trace};
use protobuf::{CodedOutputStream, Message};
use tokio_native_tls::native_tls::{TlsConnector, Certificate};
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use hyper_tls::TlsStream;
use tokio_tungstenite::WebSocketStream;

pub fn load_root_tls_cert() -> std::result::Result<Certificate, EstablishConnectionError> {
	trace!("Loading Signal's self-signed certificate.");
	Certificate::from_pem(SIGNAL_TLS_CERT.as_bytes())
		.map_err(|e| EstablishConnectionError::TlsCertFailure(format!("{:?}", e)))
}

async fn build_tls_connector(cert: Certificate) -> std::result::Result<tokio_native_tls::TlsConnector, EstablishConnectionError> {
	let mut builder = TlsConnector::builder();
	// Recognize SIGNAL_SELF_SIGNED_CERT but do not accept other invalid certs.
	builder.add_root_certificate(cert);

	let connector: tokio_native_tls::native_tls::TlsConnector = builder.build().map_err(|e| EstablishConnectionError::CannotTls(format!("{:?}", e)))?;
	Ok(tokio_native_tls::TlsConnector::from(connector))
}

async fn connect_tls_for_websocket(cert: Certificate) -> std::result::Result<TlsStream<TcpStream>, EstablishConnectionError> {
	let first_future = build_tls_connector(cert);
	let second_future = TcpStream::connect("textsecure-service.whispersystems.org:443").map_err(|e| EstablishConnectionError::CannotTls( format!("{:?}",e)));
	let (connector, stream) = tokio::try_join!(first_future, second_future)?;

	connector.connect("textsecure-service.whispersystems.org", stream).await.map_err(|e| EstablishConnectionError::CannotTls(format!("{:?}", e)))
}

// Signal's API lives at textsecure-service.whispersystems.org.
async fn connect_websocket<S: AsyncRead + AsyncWrite + Unpin>(local_identity: &LocalIdentity, stream: S) 
		-> std::result::Result<(WebSocketStream<S>, tungstenite::http::Response<()>), EstablishConnectionError> {
	let signal_url = "https://textsecure-service.whispersystems.org";

	// Make a websocket URI which has the right protocol.
	let ws_uri = signal_url
		.replace("https://", "wss://")
		.replace("http://", "ws://")
		+ "/v1/websocket/";

	// API arguments to identify ourselves.
	let mut filled_uri = ws_uri.clone();
	filled_uri.push_str("?login=");
	filled_uri.push_str(local_identity.address.get_uuid().unwrap().to_string().as_str());
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

	trace!("Connecting to websocket with request {:?}", req);
	tokio_tungstenite::client_async(req, stream).await
		.map_err(|e| EstablishConnectionError::CantStartWebsocketConnect(format!("{:?}", e)))
}

// (Try to) read a raw byte buffer as a Signal Websocketmessage protobuf.
fn read_wsmessage(buf: &[u8]) -> std::result::Result<auxin_protos::WebSocketMessage, WebsocketError> {
	let new_buf = fix_protobuf_buf(&Vec::from(buf))
		.map_err(|e| WebsocketError::FailedtoDeserialize(format!("{:?}", e)))?;
	let mut reader = protobuf::CodedInputStream::from_bytes(new_buf.as_slice());
	reader.read_message().map_err(|e| WebsocketError::FailedtoDeserialize(format!("{:?}", e)))
}

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

#[derive(Debug)]
pub enum WebsocketError { 
    FailedtoDeserialize(String),
	UnderlyingMessageReceive(String),
	TungsteniteError(tungstenite::Error),
	StreamClosed(Option<tungstenite::protocol::CloseFrame<'static>>),
}
impl fmt::Display for WebsocketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self { 
            Self::FailedtoDeserialize(e) => write!(f, "Could not deserialize to a \"Websocket Message\" protobuf: {}", e),
			Self::UnderlyingMessageReceive(e) => write!(f, "The library Auxin uses for WebSocket connections, Tungstenite, caught an error on polling for new messages: {}", e),
			Self::TungsteniteError(e) => write!(f, "{:?}", e),
			Self::StreamClosed(e) => { 
				match e {
					Some(frame) => write!(f, "Stream was closed - reason: {:?}", frame),
					None => write!(f, "Stream was closed with no close frame."),
				}
			},
        }
    }
}

impl std::error::Error for WebsocketError {}

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

pub type WsStream = WebSocketStream<TlsStream<TcpStream>>;
pub struct AuxinTungsteniteConnection { 
    client: WsStream,
}

#[async_trait]
impl AuxinWebsocketConnection for AuxinTungsteniteConnection {
    type Message = auxin_protos::WebSocketMessage;
	type SinkError= tungstenite::Error;
	type StreamError= WebsocketError;

    fn into_streams(self) -> (Pin<Box<dyn Sink<Self::Message, Error=Self::SinkError>>>, Pin<Box<dyn Stream<Item = std::result::Result<Self::Message, Self::StreamError>>>>) {
		let (sink, stream) = self.client.split();
		
		// Convert an auxin_protos::WebSocketMessage into a tungstenite::Message here. 
		let sink = sink.with( async move |m: Self::Message| 
				-> std::result::Result<tungstenite::Message, tungstenite::Error> {

			let mut buf: Vec<u8> = Vec::default();
			let mut out_gen = CodedOutputStream::new(&mut buf);
			let _ = m.compute_size();
			m.write_to_with_cached_sizes(&mut out_gen).expect("Could not write websocket message.");
			out_gen.flush().expect("Could not write websocket message.");
			drop(out_gen);
			let msg = tungstenite::Message::Binary(buf);
			Ok(msg)
		});

		// Convert a tungstenite::Message into an auxin_protos::WebSocketMessage. 
		let stream = stream.filter_map( |m | async move {
			match m { 
				Err(e) => match e { 
					tungstenite::Error::Protocol(tungstenite::error::ProtocolError::ResetWithoutClosingHandshake) => None,
					tungstenite::Error::ConnectionClosed => None,
					_ => Some(Err(WebsocketError::TungsteniteError(e)))
				},
				Ok(msg) => { 
					match msg {
						tungstenite::Message::Text(_msg) => todo!(), // From json maybe?
						tungstenite::Message::Binary(buf) => {
							Some(read_wsmessage(&buf))
						},
						tungstenite::Message::Ping(_) => None,
						tungstenite::Message::Pong(_) => None,
						tungstenite::Message::Close(frame) => Some(Err(WebsocketError::StreamClosed(frame))),
					}
				}
			}
		});

        (Box::pin(sink), Box::pin(stream))
    }
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
    TlsCertFailure(String),
    FailedHttpsConnect(String),
	CantStartWebsocketConnect(String),
	BadUpgradeResponse(String),
}
impl fmt::Display for EstablishConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self { 
            Self::CannotTls(e) => write!(f, "Failed to construct a TLS connector: {}", e),
            Self::TlsCertFailure(e) => write!(f, "Could not initialize the root Signal web API self-signed certificate: {}", e),
            Self::FailedHttpsConnect(e) => write!(f, "Could not construct an HTTPS stream: {}", e),
            Self::CantStartWebsocketConnect(e) => write!(f, "Could not initiate a websocket connection: {}", e),
            Self::BadUpgradeResponse(e) => write!(f, "Failed to connect as Websocket client, got response: {}", e),
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
		let tls_stream = connect_tls_for_websocket(load_root_tls_cert()?).await?;
        let (websocket_client, connect_response) = connect_websocket(credentials, tls_stream).await?;

		// Check to make sure our status code is success. 
		if !((connect_response.status().as_u16() == 200) || (connect_response.status().as_u16() == 101)) {
			let r = connect_response.status().as_u16();
			let s = connect_response.status().to_string();
			let err = format!("Status {}: {}", r, s);
			return Err(EstablishConnectionError::BadUpgradeResponse(err));
		}
		
		debug!("Constructed websocket client streans, got response: {:?}", connect_response);

        Ok(AuxinTungsteniteConnection{client: websocket_client})
    }
}