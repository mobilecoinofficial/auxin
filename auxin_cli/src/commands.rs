//Internal dependencies

use auxin::{
	address::AuxinAddress,
	generate_timestamp,
	message::{MessageContent, MessageIn, MessageOut},
	AuxinReceiver, Result,
};

//External dependencies

use auxin_protos::AttachmentPointer;
use log::debug;

use rand::rngs::OsRng;

use std::{convert::TryFrom, path::PathBuf};
use structopt::StructOpt;

use serde::{Deserialize, Serialize};

use crate::{initiate_attachment_downloads, ATTACHMENT_TIMEOUT_DURATION};

pub const AUTHOR_STR: &str = "Forest Contact team";
pub const VERSION_STR: &str = "0.1.2";

pub const JSONRPC_VER: &str = "2.0";

/// Command-line interface wrapper around Auxin, a developer (and bot) friendly wrapper around the Signal protocol.
#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "auxin-cli", about = "Developer (and bot) friendly wrapper around the Signal protocol.", author = AUTHOR_STR, version = VERSION_STR)]
pub struct AppArgs {
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
#[structopt(rename_all = "camel_case")]
#[serde(rename_all = "camelCase")]
pub enum AuxinCommand {
	/// Sends a message to the given address.
	Send(SendCommand),
	/// Uploads an attachment to Signal's CDN, and then prints the generated attachment pointer serialized to json.
	/// This can be used with Send --prepared-attachments later.
	Upload(UploadCommand),
	/// Polls Signal's Web API for new messages sent to your user account. Prints them to stdout.
	Receive(ReceiveCommand),
	/// Continuously polls Signal's Web API for new messages sent to your user account. Prints them to stdout.
	ReceiveLoop,
	///Attempts to get a payment address for the user with the specified phonenumber or UUID.
	GetPayAddress(GetPayAddrCommand),
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

#[derive(StructOpt, Serialize, Deserialize, Debug, Clone)]
pub struct GetPayAddrCommand {
	/// Sets the address identifying the peer whose payment address we are retrieving.
	pub peer_name: String,
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
	pub id: Option<serde_json::Value>,
	/// A string containing the name of the method to be called.
	/// In our case, this needs to be "send", "upload", "get-pay-address",  or "receive".
	pub method: String,
	/// The arguments to our command. These are the same as the command-line arguments passed to the command corresponding to the "method" field on this struct.
	pub params: serde_json::Value,
}
/// Serde_json will generate a "field=null" when serializing a field=None sort of situation, rather than just leaving it out.
/// To send a notification, it must be serialized a little differently.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcNotification {
	/// he version of the JSON-RPC protocol. MUST be exactly "2.0".
	pub jsonrpc: String,
	/// A string containing the name of the method to be called.
	/// In our case, this needs to be "send", "upload", "get-pay-address",  or "receive".
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
	pub id: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcErrorResponse {
	/// The version of the JSON-RPC protocol. MUST be exactly "2.0".
	pub jsonrpc: String,
	/// The output of the command invoked on Auxin.
	pub error: JsonRpcError,
	/// The id, which needs to be equal to the id parameter passed with the command.
	pub id: Option<serde_json::Value>,
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
				// An error should have an ID field of Null rather than just having no ID field.
				id: Some(serde_json::Value::Null),
			});
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
						// An error should have an ID field of Null rather than just having no ID field.
						id: Some(serde_json::Value::Null),
					});
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
					// An error should have an ID field of Null rather than just having no ID field.
					id: Some(serde_json::Value::Null),
				});
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
			"get-pay-address" | "getpayaddress" => {
				match serde_json::from_value::<GetPayAddrCommand>(req.params) {
					// Is this a valid parameter? 
					Ok(val) => {
						//Turn peer name into auxin address.
						match AuxinAddress::try_from(val.peer_name.as_str()) {
							Ok(peer) => {
								//Retrieve payment
								match  app.retrieve_payment_address(&peer).await {
									Ok(pay_addr_output) => JsonRpcResponse::Ok(JsonRpcGoodResponse {
										jsonrpc: JSONRPC_VER.to_string(),
										// send_output shouldn't be possible to error while encoding to json. 
										result: serde_json::to_value(pay_addr_output).unwrap(),
										id: req.id.clone(),
									}),
									Err(e) => JsonRpcResponse::Err(JsonRpcErrorResponse { 
										jsonrpc: JSONRPC_VER.to_string(),
										error: JsonRpcError {
											code: -32000,
											message: String::from("Error encountered while retrieving a payment address."),
											data: Some(serde_json::Value::String(format!("{:?}", e))),
										},
										id: req.id.clone(),
									}),
								}
							},
							Err(e) => JsonRpcResponse::Err(JsonRpcErrorResponse { 
								jsonrpc: JSONRPC_VER.to_string(),
								error: JsonRpcError {
									code: -32000,
									message: String::from("Peer address to retrieve payment for was invalid."),
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
							message: String::from("Invalid method parameter(s) for \"get-pay-address\"."),
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
