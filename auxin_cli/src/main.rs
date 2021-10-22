#![feature(async_closure)]
#![deny(bare_trait_objects)]

//Internal dependencies

use auxin::address::AuxinAddress;
use auxin::message::{MessageContent, MessageOut};
use auxin::state::AuxinStateManager;
use auxin::{Result, generate_timestamp};
use auxin::{AuxinApp, AuxinConfig, AuxinReceiver, ReceiveError};
//use auxin_protos::AttachmentPointer;

//External dependencies

use log::{debug, warn};

use rand::rngs::OsRng;

use std::path::PathBuf;
use structopt::StructOpt;
use std::cell::RefCell;
use std::convert::TryFrom;

use serde::{Serialize, Deserialize}; 

use tracing::info;
use tracing_futures::Instrument;
use tracing_subscriber::FmtSubscriber;
use tokio::time::Duration;

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

pub	const AUTHOR_STR: &str = "Forest Contact team";
pub const VERSION_STR: &str = "0.1.2";

pub const JSONRPC_VER: &str=  "2.0";

/// Command-line interface wrapper around Auxin, a developer (and bot) friendly wrapper around the Signal protocol.
#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "auxin-cli", about = "the stupid content tracker", author = AUTHOR_STR, version = VERSION_STR)]
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
    #[structopt(long = "download-path", default_value = "downloads", parse(from_os_str))]
	pub download_path: PathBuf,

	#[structopt(subcommand)]
	pub command: AuxinCommand,
}

#[derive(StructOpt,Serialize,Deserialize,Debug, Clone)]
pub enum AuxinCommand {
    /// Sends a message to the given address.
    Send (SendCommand),
	/// Uploads an attachment to Signal's CDN, and then prints the generated attachment pointer serialized to json. 
	/// This can be used with Send --prepared-attachments later. 
	Upload (UploadCommand),
	/// Polls Signal's Web API for new messages sent to your user account. Prints them to stdout. 
	Receive,
	/// A simple echo server for demonstration purposes. Loops until killed. 
	Echoserver,
	/// Launch auxin as a json-rpc 2.0 daemon. Loops until killed or until method "exit" is called.
	JsonRPC,
	/// Launches a read-evaluate-print loop, for experimentation in a development environment. 
	/// If the "repl" feature was not enabled when compiling this binary, this command will crash.
	Repl,
}

#[derive(StructOpt,Serialize,Deserialize,Debug, Clone)]
pub struct SendCommand {
	/// Sets the destination for our message (as E164-format phone number or a UUID).
	destination: String,
	/// Add one or more attachments to this message, passed in as a file path to pull from.
	#[structopt(short, long, parse(from_os_str))]
	attachments: Option<Vec<PathBuf>>,

	/// Add one or more attachments to this message, passed in as a pre-generated \"AttachmentPointer\" 
	/// Signal Service protcol buffer struct, serialized to json."
	#[structopt(long="prepared-attachments")]
	prepared_attachments: Option<Vec<String>>,

	/// Adds a text message to the SignalProtocol message we are sending..
	#[structopt(short, long)]
	message: Option<String>,
	/// Used to pass a \"Content\" protocol buffer struct from signalservice.proto, serialized as a json string.
	#[structopt(short, long)]
	content: Option<String>,
	/// Generate a Signal Service \"Content\" structure without actually sending it. Useful for testing the -c / --content option.
	#[structopt(short, long)]
	simulate: bool,
	/// Sets a flag so this message ends / resets your session with this peer.
	/// 
	/// Sets the END_SESSION flag (defined on line 109 of signalservice.proto) on this message, 
	/// which means this message will reset your session.
	/// This is the code-path which will cause a "Secure session reset" line to appear
	/// inside a standard graphical Signal client.
	#[structopt(short, long="end-session")]
	end_session: bool,
}

#[derive(StructOpt,Serialize,Deserialize,Debug, Clone)]
pub struct UploadCommand { 
	#[structopt(short, long="file-path", parse(from_os_str))]
	file_path: PathBuf, 
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

#[derive(Clone, Debug)]
pub struct SendOutput { 
	pub timestamp: u64,
	pub simulate_output: Option<String>,
}

pub async fn handle_send_command(mut cmd: SendCommand, app: &mut crate::app::App) -> std::result::Result<SendOutput, SendCommandError> {

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
	let mut premade_content: Option<auxin_protos::Content> = cmd.content
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
				.map_err(|e| { SendCommandError::AttachmentFileReadError(e) }  )?;

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
		let built_content = message.content.build_signal_content(&base64::encode(&app.context.identity.profile_key).to_string(), timestamp)
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
		//.with_max_level(Level::TRACE)
		.with_writer(std::io::stderr)
		//Ensure Tracing respects the same logging verbosity configuration environment variable as env_logger does,
		//so that one setting controls all logging in Auxin.
		.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
		// completes the builder.
		.finish();

	tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

	env_logger::init();


    let mut arguments = AppArgs::from_args();

	/*-----------------------------------------------\\
	||------------ INIT CONTEXT/IDENTITY ------------||
	\\-----------------------------------------------*/

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
			let SendOutput{timestamp, simulate_output } = handle_send_command(send_command, &mut app).await.unwrap();

			if let Some(json_out) = &simulate_output { 
				println!("Simulated generating a message with timestamp {} and generated json structure: {}", timestamp, json_out);
			}
			else {
				println!("Successfully sent Signal message with timestamp: {}", timestamp);
			}
		},
		// Uploads an attachment to Signal's CDN, and then prints the generated attachment pointer serialized to json. 
		// This can be used with Send --prepared-attachments later. 
		AuxinCommand::Upload(_upload_command) => { 
			todo!();
		},
		// Polls Signal's Web API for new messages sent to your user account. Prints them to stdout. 
		AuxinCommand::Receive => { 
			todo!();
		},
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
	
					let msg_json = serde_json::to_string_pretty(&msg).unwrap();
					println!("{}", msg_json);
	
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
		},
		// Launch auxin as a json-rpc 2.0 daemon. Loops until killed or until method "exit" is called.
		AuxinCommand::JsonRPC => { 
			todo!();
		},
		// Launches a read-evaluate-print loop, for experimentation in a development environment. 
		// If the "repl" feature was not enabled when compiling this binary, this command will crash.
		AuxinCommand::Repl => { 
			app.retrieve_sender_cert().await?;
			launch_repl(&mut app)?;
		},
	}

	app.state_manager.save_entire_context(&app.context).unwrap();

	Ok(())
}
