#![feature(async_closure)]
#![deny(bare_trait_objects)]

//Internal dependencies

use auxin::address::AuxinAddress;
use auxin::message::{MessageContent, MessageIn, MessageOut};
use auxin::state::AuxinStateManager;
use auxin::{generate_timestamp, Result};
use auxin::{AuxinApp, AuxinConfig, AuxinReceiver, ReceiveError};
//use auxin_protos::AttachmentPointer;

//External dependencies

use auxin_protos::AttachmentPointer;
use log::debug;

use rand::rngs::OsRng;

use std::cell::RefCell;
use std::convert::TryFrom;
use std::path::PathBuf;
use structopt::StructOpt;

use serde::{Deserialize, Serialize};

use tokio::time::{Duration, Instant};
use tracing::{info, Level};
use tracing_futures::Instrument;
use tracing_subscriber::FmtSubscriber;

pub mod app;
pub mod attachment;
pub mod net;
pub mod repl_wrapper;
pub mod state;

pub use crate::attachment::*;

use net::load_root_tls_cert;
pub type Context = auxin::AuxinContext;

#[cfg(feature = "repl")]
use crate::repl_wrapper::AppWrapper;

pub const AUTHOR_STR: &str = "Forest Contact team";
pub const VERSION_STR: &str = "0.1.2";

pub const JSONRPC_VER: &str = "2.0";

/// Command-line interface wrapper around Auxin, a developer (and bot) friendly wrapper around the Signal protocol.
#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "auxin-cli", about = "Developer (and bot) friendly wrapper around the Signal protocol.", author = AUTHOR_STR, version = VERSION_STR)]
struct AppArgs {
	/// Select a user id (phone number in  E164 format, for example +12345678910. UUID support is planned) from which to use auxin-cli.
	#[structopt(short, long)]
	pub user: String,

	/// Specifies which directory auxin_cli will store and retrieve
	/// stateful configuration data in, using <DIRECTORY> to select
	/// a directory. Defaults to \"./state\"
	#[structopt(short, long, default_value = "state")]
	pub config: String,

	/// Controls which directory to save downloaded attachments to as files.
	/// Defaults to \"./downloads\"
	#[structopt(
		long = "download-path",
		default_value = "downloads",
		parse(from_os_str)
	)]
	pub download_path: PathBuf,

	#[structopt(subcommand)]
	pub command: AuxinCommand,
}

#[derive(StructOpt, Serialize, Deserialize, Debug, Clone)]
pub enum AuxinCommand {
	/// Sends a message to the given address.
	Send(SendCommand),
	/// Uploads an attachment to Signal's CDN, and then prints the generated attachment pointer serialized to json.
	/// This can be used with Send --prepared-attachments later.
	Upload(UploadCommand),
	/// Continuously polls Signal's Web API for new messages sent to your user account. Prints them to stdout.
	ReceiveLoop,
	/// Polls Signal's Web API for new messages sent to your user account. Prints them to stdout.
	Receive(ReceiveCommand),
	/// A simple echo server for demonstration purposes. Loops until killed.
	Echoserver,
	/// Launch auxin as a json-rpc 2.0 daemon. Loops until killed or until method "exit" is called.
	JsonRPC,
	/// Launches a read-evaluate-print loop, for experimentation in a development environment.
	/// If the "repl" feature was not enabled when compiling this binary, this command will crash.
	Repl,
}

#[derive(StructOpt, Serialize, Deserialize, Debug, Clone)]
pub struct SendCommand {
	/// Sets the destination for our message (as E164-format phone number or a UUID).
	pub destination: String,
	/// Add one or more attachments to this message, passed in as a file path to pull from.
	#[serde(default)]
	#[structopt(short, long, parse(from_os_str))]
	pub attachments: Option<Vec<PathBuf>>,

	/// Add one or more attachments to this message, passed in as a pre-generated \"AttachmentPointer\"
	/// Signal Service protcol buffer struct, serialized to json."
	#[structopt(long = "prepared-attachments")]
	#[serde(default)]
	pub prepared_attachments: Option<Vec<String>>,

	/// Adds a text message to the SignalProtocol message we are sending..
	#[structopt(short, long)]
	#[serde(default)]
	pub message: Option<String>,
	/// Used to pass a \"Content\" protocol buffer struct from signalservice.proto, serialized as a json string.
	#[structopt(short, long)]
	#[serde(default)]
	pub content: Option<String>,
	/// Generate a Signal Service \"Content\" structure without actually sending it. Useful for testing the -c / --content option.
	#[structopt(short, long)]
	#[serde(default)]
	pub simulate: bool,
	/// Sets a flag so this message ends / resets your session with this peer.
	///
	/// Sets the END_SESSION flag (defined on line 109 of signalservice.proto) on this message,
	/// which means this message will reset your session.
	/// This is the code-path which will cause a "Secure session reset" line to appear
	/// inside a standard graphical Signal client.
	#[structopt(short, long = "end-session")]
	#[serde(default)]
	pub end_session: bool,
}

#[derive(StructOpt, Serialize, Deserialize, Debug, Clone)]
pub struct UploadCommand {
	/// The path for the file (or files) to upload.
	#[structopt(short, long = "file-path", parse(from_os_str))]
	#[serde(default)]
	pub file_path: Vec<PathBuf>,
}

#[derive(StructOpt, Serialize, Deserialize, Debug, Clone)]
pub struct ReceiveCommand {
	/// Skip actually downloading attachment, and instead print AttachmentPointer structures which can be used later.
	#[structopt(short, long = "no-download")]
	#[serde(default)]
	pub no_download: bool,
}

#[derive(Debug)]
// Errors received when attempting to send a Signal message to another user.
pub enum SendCommandError {
	//Propagated through from app,send_message()
	SendError(auxin::SendMessageError),
	AttachmentUploadError(auxin::attachment::upload::AttachmentUploadError),
	AttachmentEncryptError(auxin::attachment::upload::AttachmentEncryptError),
	AttachmentFileReadError(std::io::Error),
	SimulateErr(String),
}

impl std::fmt::Display for SendCommandError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match &self {
			SendCommandError::SendError(e) => write!(f, "Error encountered in app.send_message(): {:?}", e),
			SendCommandError::AttachmentUploadError(e) => write!(f, "Attempt to upload an attachment while sending a message failed with error: {:?}", e),
			SendCommandError::AttachmentEncryptError(e) => write!(f, "Attempt to upload an attachment while sending a message failed with error: {:?}", e),
			SendCommandError::AttachmentFileReadError(e) => write!(f, "Tried to load a file to upload as an attachment (to send on a message), but an error was encountered while opening the file: {:?}", e),
			SendCommandError::SimulateErr(e) => write!(f, "Serializing a Signal message content to a json structure for the --simulate argument failed: {:?}", e),
		}
	}
}
impl std::error::Error for SendCommandError {}
// Just a bit of boilerplate
impl From<auxin::SendMessageError> for SendCommandError {
	fn from(val: auxin::SendMessageError) -> Self {
		SendCommandError::SendError(val)
	}
}
impl From<auxin::attachment::upload::AttachmentUploadError> for SendCommandError {
	fn from(val: auxin::attachment::upload::AttachmentUploadError) -> Self {
		SendCommandError::AttachmentUploadError(val)
	}
}
impl From<auxin::attachment::upload::AttachmentEncryptError> for SendCommandError {
	fn from(val: auxin::attachment::upload::AttachmentEncryptError) -> Self {
		SendCommandError::AttachmentEncryptError(val)
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SendOutput {
	pub timestamp: u64,
	pub simulate_output: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcRequest {
	/// he version of the JSON-RPC protocol. MUST be exactly "2.0".
	pub jsonrpc: String,
	/// An identifier used to track this request, so that when we give the JsonRPC client the result in return it should be possible
	/// to correlate this request to that response.
	/// A Request object without an "id" is a "Notification." Notification objects do not need to receive a response.
	pub id: serde_json::Value,
	/// A string containing the name of the method to be called.
	/// In our case, this needs to be "send", "upload", or "receive".
	pub method: String,
	/// The arguments to our command. These are the same as the command-line arguments passed to the command corresponding to the "method" field on this struct.
	pub params: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcError {
	/// The type of error that occured.
	pub code: i32,
	///A short description of the error.
	pub message: String,
	/// A more detailed, possibly-structured description of the error.
	pub data: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcGoodResponse {
	/// The version of the JSON-RPC protocol. MUST be exactly "2.0".
	pub jsonrpc: String,
	/// The output of the command invoked on Auxin.
	pub result: serde_json::Value,
	/// The id, which needs to be equal to the id parameter passed with the command.
	pub id: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcErrorResponse {
	/// The version of the JSON-RPC protocol. MUST be exactly "2.0".
	pub jsonrpc: String,
	/// The output of the command invoked on Auxin.
	pub error: JsonRpcError,
	/// The id, which needs to be equal to the id parameter passed with the command.
	pub id: serde_json::Value,
}

pub enum JsonRpcResponse {
	Ok(JsonRpcGoodResponse),
	Err(JsonRpcErrorResponse),
}

pub async fn process_jsonrpc_input(
	input: &str,
	app: &mut crate::app::App,
	download_path: &PathBuf,
) -> Vec<JsonRpcResponse> {
	fn err(e: JsonRpcErrorResponse) -> Vec<JsonRpcResponse> {
		vec![JsonRpcResponse::Err(e)]
	}
	// Initial parsing pass, get a json value so we can see if it's an object (single command) or an array (batch)
	let command_or_commands: serde_json::Value = match serde_json::from_str(input) {
		Ok(val) => val,
		Err(e) => {
			return err(JsonRpcErrorResponse {
				jsonrpc: JSONRPC_VER.to_string(),
				error: JsonRpcError {
					code: -32700,
					message: String::from("Invalid JSON was received by the server."),
					data: Some(serde_json::Value::String(format!("{:?}", e))),
				},
				id: serde_json::Value::Null,
			})
		}
	};

	let mut requests: Vec<JsonRpcRequest> = Vec::default();
	// If this is a batch request / array of requests, iterate through values in the array and put them to our list.
	if let serde_json::Value::Array(arr) = &command_or_commands {
		for val in arr {
			let request: JsonRpcRequest = match serde_json::from_value(val.clone()) {
				Ok(val) => val,
				Err(e) => {
					return err(JsonRpcErrorResponse {
						jsonrpc: JSONRPC_VER.to_string(),
						error: JsonRpcError {
							code: -32600,
							message: String::from("The JSON sent is not a valid Request object."),
							data: Some(serde_json::Value::String(format!("{:?}", e))),
						},
						id: serde_json::Value::Null,
					})
				}
			};

			requests.push(request);
		}
	}
	// Otherwise, just decode a single command object
	else {
		let request: JsonRpcRequest = match serde_json::from_value(command_or_commands) {
			Ok(val) => val,
			Err(e) => {
				return err(JsonRpcErrorResponse {
					jsonrpc: JSONRPC_VER.to_string(),
					error: JsonRpcError {
						code: -32600,
						message: String::from("The JSON sent is not a valid Request object."),
						data: Some(serde_json::Value::String(format!("{:?}", e))),
					},
					id: serde_json::Value::Null,
				})
			}
		};
		requests.push(request);
	}

	let mut output = Vec::default();

	// We should now have one or more valid JsonRPC commands. Let's see if any of them match our method.
	for req in requests {
		let lowercase = req.method.to_ascii_lowercase();
		let methodstr = lowercase.as_str();
		let response = match methodstr { 
			"send" => {
				match serde_json::from_value::<SendCommand>(req.params) {
					// Is this a valid parameter? 
					Ok(val) => {
						// Actually do send behavior. 
						let send_result = handle_send_command(val, app).await;
						match send_result {
							Ok(send_output) => JsonRpcResponse::Ok(JsonRpcGoodResponse {
								jsonrpc: JSONRPC_VER.to_string(),
								// send_output shouldn't be possible to error while encoding to json. 
								result: serde_json::to_value(send_output).unwrap(),
								id: req.id.clone(),
							}),
							Err(e) => JsonRpcResponse::Err(JsonRpcErrorResponse { 
								jsonrpc: JSONRPC_VER.to_string(),
								error: JsonRpcError {
									code: -32000,
									message: String::from("Error encountered while sending message."),
									data: Some(serde_json::Value::String(format!("{:?}", e))),
								},
								id: req.id.clone(),
							}),
						}
					}, 
					// Could not decode params
					Err(e) => JsonRpcResponse::Err(JsonRpcErrorResponse { 
						jsonrpc: JSONRPC_VER.to_string(),
						error: JsonRpcError {
							code: -32602,
							message: String::from("Invalid method parameter(s) for \"send\"."),
							data: Some(serde_json::Value::String(format!("{:?}", e))),
						},
						id: req.id.clone(),
					}),
				}
			},
			"upload" => {
				match serde_json::from_value::<UploadCommand>(req.params) {
					// Is this a valid parameter? 
					Ok(val) => {
						// Actually do send behavior. 
						let upload_output = handle_upload_command(val, app).await;
						match upload_output {
							Ok(attachment_pointers) => JsonRpcResponse::Ok(JsonRpcGoodResponse {
								jsonrpc: JSONRPC_VER.to_string(),
								// send_output shouldn't be possible to error while encoding to json. 
								result: serde_json::to_value(attachment_pointers).unwrap(),
								id: req.id.clone(),
							}),
							Err(e) => JsonRpcResponse::Err(JsonRpcErrorResponse { 
								jsonrpc: JSONRPC_VER.to_string(),
								error: JsonRpcError {
									code: -32000,
									message: String::from("Error encountered while attempting to upload files."),
									data: Some(serde_json::Value::String(format!("{:?}", e))),
								},
								id: req.id.clone(),
							}),
						}
					}, 
					// Could not decode params
					Err(e) => JsonRpcResponse::Err(JsonRpcErrorResponse { 
						jsonrpc: JSONRPC_VER.to_string(),
						error: JsonRpcError {
							code: -32602,
							message: String::from("Invalid method parameter(s) for \"upload\"."),
							data: Some(serde_json::Value::String(format!("{:?}", e))),
						},
						id: req.id.clone(),
					}),
				}
			},
			"receive" => {
				let params = if req.params.is_null() { 
					std::result::Result::Ok(ReceiveCommand{ no_download: false })
				} else { 
					serde_json::from_value::<ReceiveCommand>(req.params)
				};
				match params {
					// Is this a valid parameter? 
					Ok(val) => {
						// Actually do send behavior. 
						let receive_output = handle_receive_command(val, download_path, app).await;
						match receive_output {
							Ok(messages) => JsonRpcResponse::Ok(JsonRpcGoodResponse {
								jsonrpc: JSONRPC_VER.to_string(),
								// receive output shouldn't be possible to error while encoding to json. 
								result: serde_json::to_value(messages).unwrap(),
								id: req.id.clone(),
							}),
							Err(e) => JsonRpcResponse::Err(JsonRpcErrorResponse { 
								jsonrpc: JSONRPC_VER.to_string(),
								error: JsonRpcError {
									code: -32000,
									message: String::from("Error encountered while attempting to receive messages."),
									data: Some(serde_json::Value::String(format!("{:?}", e))),
								},
								id: req.id.clone(),
							}),
						}
					}, 
					// Could not decode params
					Err(e) => JsonRpcResponse::Err(JsonRpcErrorResponse { 
						jsonrpc: JSONRPC_VER.to_string(),
						error: JsonRpcError {
							code: -32602,
							message: String::from("Invalid method parameter(s) for \"receive\"."),
							data: Some(serde_json::Value::String(format!("{:?}", e))),
						},
						id: req.id.clone(),
					}),
				}
			},
			// Not a valid command! 
			_ => JsonRpcResponse::Err(JsonRpcErrorResponse { 
				jsonrpc: JSONRPC_VER.to_string(),
				error: JsonRpcError {
					code: -32601,
					message: format!("The method you provided (which is {}) does not exist - please use \"send\", \"upload\", or \"receive\".", methodstr),
					data: None,
				},
				id: req.id.clone(),
			}),
		};
		output.push(response);
	}

	output
}

pub async fn handle_send_command(
	mut cmd: SendCommand,
	app: &mut crate::app::App,
) -> std::result::Result<SendOutput, SendCommandError> {
	// Ensure we're not trying to send *just* an end-session message with no text,
	// which is not supported by  Signal's protocol
	if cmd.end_session && cmd.message.is_none() {
		debug!("End-session flag with no message, setting message to \"TERMINATE\"");
		cmd.message = Some("TERMINATE".to_string());
	}

	//Set up our address
	let recipient_addr = AuxinAddress::try_from(cmd.destination.as_str()).unwrap();

	//MessageContent
	let mut message_content = MessageContent::default();

	//Do we want to end our session here?
	message_content.end_session = cmd.end_session;

	//Do we have a regular text message?
	message_content.text_message = cmd.message;

	//Did the user pass in a "Content" protocol buffer serialized as json?
	let mut premade_content: Option<auxin_protos::Content> = cmd
		.content
		.map(|s| serde_json::from_str(s.as_ref()).unwrap());

	// TODO: PARALLELIZE ATTACHMENT DOWNLOADS

	//Do we have one or more attachments?
	//Note the use of values_of rather than value_of because there may be more than one of these.
	if let Some(to_attach) = cmd.attachments {
		//Iterate over each attachment.
		for att in to_attach.into_iter() {
			let upload_attributes = app.request_upload_id().await?;
			let file_path_str = att;
			let file_path = std::path::Path::new(&file_path_str);
			let file_name = file_path.file_name().unwrap().to_str().unwrap();

			let data = std::fs::read(&file_path)
				.map_err(|e| SendCommandError::AttachmentFileReadError(e))?;

			//Encrypt our attachment.
			let mut rng = OsRng::default();
			let encrypted_attahcment =
				auxin::attachment::upload::encrypt_attachment(file_name, &data, &mut rng)?;

			//Upload the attachment, generating an attachment pointer in the process.
			let attachment_pointer = app
				.upload_attachment(&upload_attributes, &encrypted_attahcment)
				.await?;

			//If we have a premade content, put the attachments there instead.
			if let Some(c) = &mut premade_content {
				if !c.has_dataMessage() {
					c.set_dataMessage(auxin_protos::DataMessage::default());
				}
				c.mut_dataMessage().attachments.push(attachment_pointer);
			} else {
				//Otherwise, we are constructing content regularly.

				//Add it to our list!
				message_content.attachments.push(attachment_pointer);
			}
		}
	}

	//Wrap our message content in one of these.
	let mut message = MessageOut {
		content: message_content,
	};

	if premade_content.is_some() {
		debug!("Using premade content {:?}", premade_content);
	}
	//If there was no premade content there is no other reason for a MessageOut to have a "source" other than None.
	message.content.source = premade_content;

	Ok(if cmd.simulate {
		let timestamp = generate_timestamp();
		//Are we just testing this thing? If so, print our content as json.
		let built_content = message
			.content
			.build_signal_content(
				&base64::encode(&app.context.identity.profile_key).to_string(),
				timestamp,
			)
			.map_err(|e| SendCommandError::SimulateErr(format!("{:?}", e)))?;

		let content_str = serde_json::to_string(&built_content)
			.map_err(|e| SendCommandError::SimulateErr(format!("{:?}", e)))?;
		SendOutput {
			timestamp,
			simulate_output: Some(content_str),
		}
	} else {
		//Not just testing, no -s argument, actually send our message.
		let timestamp = app.send_message(&recipient_addr, message).await?;
		SendOutput {
			timestamp,
			simulate_output: None,
		}
	})
}

pub async fn handle_upload_command(
	cmd: UploadCommand,
	app: &mut crate::app::App,
) -> Result<Vec<AttachmentPointer>> {
	let mut attachments: Vec<AttachmentPointer> = Vec::default();
	for path in cmd.file_path.iter() {
		let mut rng = OsRng::default();
		let upload_attributes = app.request_upload_id().await?;

		let data = std::fs::read(path)?;

		let file_name = path.file_name().unwrap();

		let encrypted_attahcment = auxin::attachment::upload::encrypt_attachment(
			file_name.to_str().unwrap(),
			&data,
			&mut rng,
		)?;

		// TODO: Refactor Auxin's HTTP client ownership to permit greater parallelism
		let attachment_pointer = app
			.upload_attachment(&upload_attributes, &encrypted_attahcment)
			.await?;
		attachments.push(attachment_pointer);
	}
	Ok(attachments)
}

pub async fn handle_receive_command(
	cmd: ReceiveCommand,
	download_path: &PathBuf,
	app: &mut crate::app::App,
) -> Result<Vec<MessageIn>> {
	let mut attachments_to_download: Vec<AttachmentPointer> = Vec::default();

	let mut messages: Vec<MessageIn> = Vec::default();
	let mut receiver = AuxinReceiver::new(app).await.unwrap();
	while let Some(msg) = receiver.next().await {
		let msg = msg.unwrap();
		attachments_to_download.extend_from_slice(&msg.content.attachments);
		messages.push(msg);
	}

	//Download all attachments
	if !(cmd.no_download || attachments_to_download.is_empty()) {
		let pending_downloads = initiate_attachment_downloads(
			attachments_to_download,
			download_path.to_str().unwrap().to_string(),
			app.get_http_client(),
			Some(ATTACHMENT_TIMEOUT_DURATION),
		);

		//Force all downloads to complete.
		futures::future::try_join_all(pending_downloads.into_iter()).await?;
	}

	Ok(messages)
}

pub static ATTACHMENT_TIMEOUT_DURATION: Duration = Duration::from_secs(48);

#[cfg(feature = "repl")]
pub fn launch_repl(app: &mut crate::app::App) -> Result<()> {
	use papyrus::repl;

	let mut app = AppWrapper { app_inner: app };

	let mut repl = repl!(AppWrapper);

	let mut library_dir: String = "target/".into();

	#[cfg(debug_assertions)]
	library_dir.push_str("debug/");
	#[cfg(not(debug_assertions))]
	library_dir.push_str("release/");

	let mut auxin_cli_lib_dir = library_dir.clone();
	auxin_cli_lib_dir.push_str("libauxin_cli.rlib");
	let auxin_cli_lib = papyrus::linking::Extern::new(&auxin_cli_lib_dir)?; //papyrus::linking::Extern::new(&auxin_lib_dir)?;

	let mut auxin_lib_dir = library_dir.clone();
	auxin_lib_dir.push_str("libauxin.rlib");
	let auxin_lib = papyrus::linking::Extern::new(&auxin_lib_dir)?; //papyrus::linking::Extern::new(&auxin_lib_dir)?;)?;

	let mut auxin_proto_lib_dir = library_dir.clone();
	auxin_proto_lib_dir.push_str("libauxin_protos.rlib");
	let auxin_proto_lib = papyrus::linking::Extern::new(&auxin_proto_lib_dir)?; //papyrus::linking::Extern::new(&auxin_lib_dir)?;

	repl.data.with_external_lib(auxin_cli_lib);
	repl.data.with_external_lib(auxin_lib);
	repl.data.with_external_lib(auxin_proto_lib);

	repl.run(papyrus::run::RunCallbacks::new(&mut app))?;

	Ok(())
}
#[cfg(not(feature = "repl"))]
pub fn launch_repl(_app: &mut crate::app::App) -> Result<()> {
	panic!("Attempted to launch a REPL, but the 'repl' feature was not enabled at compile-time!")
}

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<()> {
	/*-----------------------------------------------\\
	||------------ LOGGER INITIALIZATION ------------||
	\\-----------------------------------------------*/
	let subscriber = FmtSubscriber::builder()
		// all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
		// will be written to stdout.
		.with_max_level(Level::TRACE)
		.with_writer(std::io::stderr)
		//Ensure Tracing respects the same logging verbosity configuration environment variable as env_logger does,
		//so that one setting controls all logging in Auxin.
		.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
		// completes the builder.
		.finish();

	tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

	env_logger::init();

	/*-----------------------------------------------\\
	||------------ INIT CONTEXT/IDENTITY ------------||
	\\-----------------------------------------------*/

	let arguments = AppArgs::from_args();

	let base_dir = format!("{}/data", arguments.config.as_str());
	debug!(
		"Using {} as the directory which holds our Signal protocol state.",
		base_dir
	);

	let cert = load_root_tls_cert().unwrap();
	let net = crate::net::NetManager::new(cert);
	let state = crate::state::StateManager::new(&base_dir);
	// Get it to all come together.
	let mut app = AuxinApp::new(
		arguments.user.clone(),
		AuxinConfig {},
		net,
		state,
		OsRng::default(),
	)
	.instrument(tracing::info_span!("AuxinApp"))
	.await
	.unwrap();

	/*-----------------------------------------------\\
	||--------------- COMMAND DISPATCH --------------||
	\\-----------------------------------------------*/

	// This is the only place commands which initiate an infinite loop or otherwise
	// take over program flow are handled. Anything which should not be available
	// within json-rpc (including the command to start a json-rpc daemon) goes here.
	// As of 0.1.2, that is Echoserver, JsonRPC, and REPL.

	match arguments.command {
		// Sends a message to the given address.
		AuxinCommand::Send(send_command) => {
			let SendOutput {
				timestamp,
				simulate_output,
			} = handle_send_command(send_command, &mut app).await.unwrap();

			if let Some(json_out) = &simulate_output {
				println!("Simulated generating a message with timestamp {} and generated json structure: {}", timestamp, json_out);
			} else {
				println!(
					"Successfully sent Signal message with timestamp: {}",
					timestamp
				);
			}
		}
		// Uploads an attachment to Signal's CDN, and then prints the generated attachment pointer serialized to json.
		// This can be used with Send --prepared-attachments later.
		AuxinCommand::Upload(upload_command) => {
			let start_time = Instant::now();
			let attachments = handle_upload_command(upload_command, &mut app).await?;

			let json_attachment_pointer = serde_json::to_string_pretty(&attachments)?;
			println!("{}", json_attachment_pointer);

			info!(
				"Uploaded attachments in {} milliseconds.",
				start_time.elapsed().as_millis()
			);
		}

		AuxinCommand::ReceiveLoop => {
			let exit = false;
			let receiver_main = RefCell::new(Some(AuxinReceiver::new(&mut app).await.unwrap()));
			while !exit {
				let receiver = receiver_main.take();
				let mut receiver = receiver.unwrap();
				while let Some(msg) = receiver.next().await {
					let msg = msg.unwrap();
					let msg_json = serde_json::to_string(&msg).unwrap();
					println!("{}", msg_json);
				}
				let sleep_time = Duration::from_millis(100);
				tokio::time::sleep(sleep_time).await;

				if let Err(e) = receiver.refresh().await {
					log::warn!("Suppressing error on attempting to retrieve more messages - attempting to reconnect instead. Error was: {:?}", e);
					receiver
						.reconnect()
						.await
						.map_err(|e| ReceiveError::ReconnectErr(format!("{:?}", e)))
						.unwrap();
				}

				receiver_main.replace(Some(receiver));
			}
		}

		// Polls Signal's Web API for new messages sent to your user account. Prints them to stdout.
		AuxinCommand::Receive(receive_command) => {
			let messages =
				handle_receive_command(receive_command, &arguments.download_path, &mut app).await?;
			let messages_json = serde_json::to_string(&messages)?;
			println!("{}", messages_json);
		}
		// A simple echo server for demonstration purposes. Loops until killed.
		AuxinCommand::Echoserver => {
			let exit = false;
			// Ugly hack to get around the multiple ways the borrow checker doesn't recognize what we're trying to do.
			let receiver_main = RefCell::new(Some(AuxinReceiver::new(&mut app).await.unwrap()));
			while !exit {
				let receiver = receiver_main.take();
				let mut receiver = receiver.unwrap();
				while let Some(msg) = receiver.next().await {
					let msg = msg.unwrap();

					let msg_json = serde_json::to_string(&msg).unwrap();
					println!("{}", msg_json);

					if msg.content.receipt_message.is_none() {
						if let Some(st) = msg.content.text_message {
							info!("Message received with text \"{}\", replying...", st);
							receiver
								.send_message(
									&msg.remote_address.address,
									MessageOut {
										content: MessageContent::default().with_text(st.clone()),
									},
								)
								.await
								.unwrap();
						}
					}
				}

				let sleep_time = Duration::from_millis(100);
				tokio::time::sleep(sleep_time).await;

				if let Err(e) = receiver.refresh().await {
					log::warn!("Suppressing error on attempting to retrieve more messages - attempting to reconnect instead. Error was: {:?}", e);
					receiver
						.reconnect()
						.await
						.map_err(|e| ReceiveError::ReconnectErr(format!("{:?}", e)))
						.unwrap();
				}

				receiver_main.replace(Some(receiver));
			}
		}
		// Launch auxin as a json-rpc 2.0 daemon. Loops until killed or until method "exit" is called.
		AuxinCommand::JsonRPC => {
			// Infinite loop
			loop {
				let stdin = tokio::io::stdin();
				let reader = tokio::io::BufReader::new(stdin);
				let mut lines = tokio::io::AsyncBufReadExt::lines(reader);

				let input_maybe = lines.next_line().await?;

				if let Some(input) = input_maybe {
					let output_list =
						process_jsonrpc_input(input.as_str(), &mut app, &arguments.download_path)
							.await;
					for entry in output_list {
						match entry {
							JsonRpcResponse::Ok(result) => {
								let result_str = serde_json::to_string(&result)?;
								println!("{}", result_str);
							}
							JsonRpcResponse::Err(result) => {
								let result_str = serde_json::to_string(&result)?;
								println!("{}", result_str);
							}
						}
					}
				}
			}
		}
		// Launches a read-evaluate-print loop, for experimentation in a development environment.
		// If the "repl" feature was not enabled when compiling this binary, this command will crash.
		AuxinCommand::Repl => {
			app.retrieve_sender_cert().await?;
			launch_repl(&mut app)?;
		}
	}
	app.state_manager.save_entire_context(&app.context).unwrap();
	Ok(())
}
