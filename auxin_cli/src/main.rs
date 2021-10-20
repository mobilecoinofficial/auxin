#![feature(async_closure)]
#![deny(bare_trait_objects)]

use log::{debug, warn};
use std::cell::RefCell;
use std::convert::TryFrom;
use tokio::time::Duration;

use auxin::address::AuxinAddress;
use auxin::message::{MessageContent, MessageOut};
use auxin::state::AuxinStateManager;
use auxin::{generate_timestamp, Result};
use auxin::{AuxinApp, AuxinConfig, AuxinReceiver, ReceiveError};
use auxin_protos::AttachmentPointer;
use rand::rngs::OsRng;

use tracing::info;
use tracing_futures::Instrument;
use tracing_subscriber::FmtSubscriber;

use clap::{Arg, SubCommand};

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
	const AUTHOR_STR: &str = "Forest Contact team";
	const VERSION_STR: &str = "0.1.1";

	let args = clap::App::new("auxin-cli")
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
						.arg(Arg::with_name("CONFIG")
							.long("config")
							.short("c")
							.takes_value(true)
							.default_value("state")
							.value_name("DIRECTORY")
							.help("Specifies which directory auxin_cli will store and retrieve stateful configuration data in, using <DIRECTORY> to select a directory. Defaults to \"./state\""))
						.subcommand(SubCommand::with_name("send")
							.about("Sends a message to the specified address.")
							.version(VERSION_STR)
							.author(AUTHOR_STR)
							.args_from_usage("<DESTINATION> 'Sets the destination for our message'")
							.arg(Arg::with_name("MESSAGE")
								.short("m")
								.long("message")
								.value_name("MESSAGE_BODY")
								.required(false)
								.takes_value(true)
								.help("Determines the message text we will send."))
							.arg(Arg::with_name("ATTACHMENT")
								.short("a")
								.long("attachment")
								.value_name("FILE_PATH")
								.required(false)
								.takes_value(true)
								.multiple(true) //Add one or more attachment.
								.help("Add one or more attachments to this message, using <FILE_PATH> to select a file"))
							.arg(Arg::with_name("CONTENT")
								.short("c")
								.long("content")
								.value_name("CONTENT_STRUCTURE")
								.required(false)
								.takes_value(true)
								.help("Used to pass a \"Content\" protocol buffer struct from signalservice.proto, serialized as a json string."))
							.arg(Arg::with_name("SIMULATE")
								.short("s")
								.long("simulate")
								.required(false)
								.takes_value(false)
								.help("Generate a Signal Service \"Content\" structure without actually sending it. Useful for testing the -c / --content option."))
							.arg(Arg::with_name("END_SESSION")
								.short("e")
								.long("end_session")
								.required(false)
								.takes_value(false)
								.help("Sets the END_SESSION flag (defined on line 109 of signalservice.proto) on this message, which means this message will reset your session with this peer."))

						).subcommand(SubCommand::with_name("upload")
							.about("Uploads an attachment to Signal's CDN.")
							.version(VERSION_STR)
							.author(AUTHOR_STR)
							.args_from_usage("<FILEPATH> 'Specifies the path to the file we are uploading.'")
						).subcommand(SubCommand::with_name("getpayaddress")
							.about("Attempts to get a payment address for the user with the specified phonenumber or UUID.")
							.version(VERSION_STR)
							.author(AUTHOR_STR)
							.args_from_usage("<PEER> 'Address of the peer whose payment address we're retrieving.'")
						).subcommand(SubCommand::with_name("receive")
							.about("Polls for incoming messages.")
							.version(VERSION_STR)
							.author(AUTHOR_STR)
						).subcommand(SubCommand::with_name("echoserver")
							.about("A simple echo server for demonstration purposes.")
							.version(VERSION_STR)
							.author(AUTHOR_STR)
						).subcommand(SubCommand::with_name("repl")
							.about("Launch a read-evaluate-print loop.")
							.version(VERSION_STR)
							.author(AUTHOR_STR))
						.get_matches();

	let our_phone_number = args.value_of("USER")
		.expect("Must select a user ID! Input either your UUID or your phone number (in E164 format, i.e. +[country code][phone number])");
	let our_phone_number = our_phone_number.to_string();

	env_logger::init();

	let base_dir = format!("{}/data", args.value_of("CONFIG").unwrap());
	debug!(
		"Using {} as the directory which holds our Signal protocol state.",
		base_dir
	);

	let cert = load_root_tls_cert().unwrap();
	let net = crate::net::NetManager::new(cert);
	let state = crate::state::StateManager::new(&base_dir);
	// Get it to all come together.
	let mut app = AuxinApp::new(
		our_phone_number,
		AuxinConfig {},
		net,
		state,
		OsRng::default(),
	)
	.instrument(tracing::info_span!("AuxinApp"))
	.await
	.unwrap();

	//Prepare to download attachments, asynchronously.
	if let Some(send_command) = args.subcommand_matches("send") {
		let dest = send_command.value_of("DESTINATION").unwrap();
		let recipient_addr = AuxinAddress::try_from(dest).unwrap();

		//Are we actually going to send a message, or just see what it'd be like if we did? 
		let simulate: bool = send_command.is_present("SIMULATE");

		let mut message_content = MessageContent::default();

		//Do we want to end our session here? 
		if !simulate && send_command.is_present("END_SESSION") {
			message_content.end_session = true; 
		}
		else { 
			message_content.end_session = false;
		}


		//Do we have a regular text message?
		let message_text: Option<&str> = send_command.value_of("MESSAGE");
		message_content.text_message = message_text.map(|s| s.to_string());

		//Did the user pass in a "Content" protocol buffer serialized as json?
		let mut premade_content: Option<auxin_protos::Content> = send_command
			.value_of("CONTENT")
			.map(|s| serde_json::from_str(s).unwrap());
		//Do we have one or more attachments?
		//Note the use of values_of rather than value_of because there may be more than one of these.
		let maybe_attach = send_command.values_of("ATTACHMENT");
		if let Some(to_attach) = maybe_attach {
			//Iterate over each attachment.
			for att in to_attach.into_iter() {
				let upload_attributes = app.request_upload_id().await?;
				let file_path_str = att;
				let file_path = std::path::Path::new(&file_path_str);
				let file_name = file_path.file_name().unwrap().to_str().unwrap();

				let data = std::fs::read(&file_path)?;

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

		if simulate { 
			//Are we just testing this thing? If so, print our content as json. 
			let built_content = message.content.build_signal_content(&base64::encode(&app.context.identity.profile_key).to_string(), generate_timestamp())?;

			println!("[CONTENT_PRODUCED]");
			let content_str = serde_json::to_string(&built_content)?;
			println!("{}", content_str);
		} else {
			//Not just testing, no -s argument, actually send our message.
			app.send_message(&recipient_addr, message).await.unwrap();
		}
	}

	if let Some(payaddr_command) = args.subcommand_matches("getpayaddress") {
		warn!("The \"getpayaddress\" command is still experimental! Please do not use this command in production.");
		let dest = payaddr_command.value_of("PEER").unwrap();
		let recipient_addr = AuxinAddress::try_from(dest).unwrap();
		let payment_address = app.retrieve_payment_address(&recipient_addr).await.unwrap();
		let payaddr_json = serde_json::to_string(&payment_address).unwrap();

		println!("[PAYMENT_ADDRESS]");
		println!("{}", payaddr_json);
	}

	let mut attachments_to_download: Vec<AttachmentPointer> = Vec::default();

	if args.subcommand_matches("receive").is_some() {
		let mut receiver = AuxinReceiver::new(&mut app).await.unwrap();
		while let Some(msg) = receiver.next().await {
			let msg = msg.unwrap();

			attachments_to_download.extend_from_slice(&msg.content.attachments);

			if let Some(msg) = &msg.content.text_message {
				info!("Message received with text {}", msg);
			}
			let msg_json = serde_json::to_string_pretty(&msg).unwrap();
			println!("[MESSAGE]");
			println!("{}", msg_json);
		}
	}

	if !attachments_to_download.is_empty() {
		let pending_downloads = initiate_attachment_downloads(
			attachments_to_download,
			app.get_http_client(),
			Some(ATTACHMENT_TIMEOUT_DURATION),
		);

		//Force all downloads to complete.
		futures::future::try_join_all(pending_downloads.into_iter()).await?;
	}

	if let Some(send_command) = args.subcommand_matches("upload") {
		let upload_attributes = app.request_upload_id().await?;
		let file_path_str = send_command.value_of("FILEPATH").unwrap();
		let file_path = std::path::Path::new(&file_path_str);
		let file_name = file_path.file_name().unwrap().to_str().unwrap();

		let data = std::fs::read(&file_path)?;

		let mut rng = OsRng::default();

		let encrypted_attahcment =
			auxin::attachment::upload::encrypt_attachment(file_name, &data, &mut rng)?;

		let attachment_pointer = app
			.upload_attachment(&upload_attributes, &encrypted_attahcment)
			.await?;
		println!("[ATTACHMENT_POINTER]");
		println!("{:?}", attachment_pointer);
	}

	if args.subcommand_matches("echoserver").is_some() {
		let mut exit = false;
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
					if st.eq_ignore_ascii_case("/stop") {
						exit = true;
					} else {
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

	if args.subcommand_matches("repl").is_some() {
		app.retrieve_sender_cert().await?;
		launch_repl(&mut app)?;
	}

	app.state_manager.save_entire_context(&app.context).unwrap();

	Ok(())
}
