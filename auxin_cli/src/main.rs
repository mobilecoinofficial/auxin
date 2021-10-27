#![feature(async_closure)]
#![deny(bare_trait_objects)]

//Internal dependencies

use auxin::{
	address::AuxinAddress,
	message::{MessageContent, MessageOut},
	state::AuxinStateManager,
	AuxinApp, AuxinConfig, AuxinReceiver, ReceiveError, Result,
};

//External dependencies

use log::debug;

use rand::rngs::OsRng;

use std::{cell::RefCell, convert::TryFrom};

use structopt::StructOpt;

use tokio::time::{Duration, Instant};
use tracing::info;
use tracing_futures::Instrument;
use tracing_subscriber::FmtSubscriber;

pub mod app;
pub mod attachment;
pub mod commands;
pub mod net;
pub mod repl_wrapper;
pub mod state;

pub use crate::commands::*;
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
		},
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
		},
		// Polls Signal's Web API for new messages sent to your user account. Prints them to stdout.
		AuxinCommand::Receive(receive_command) => {
			let messages =
				handle_receive_command(receive_command, &arguments.download_path, &mut app).await?;
			let messages_json = serde_json::to_string_pretty(&messages)?;
			println!("{}", messages_json);
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
								let result_str = serde_json::to_string_pretty(&result)?;
								println!("{}", result_str);
							}
							JsonRpcResponse::Err(result) => {
								let result_str = serde_json::to_string_pretty(&result)?;
								println!("{}", result_str);
							}
						}
					}
				}
			}
		},
		// Launches a read-evaluate-print loop, for experimentation in a development environment.
		// If the "repl" feature was not enabled when compiling this binary, this command will crash.
		AuxinCommand::Repl => {
			app.retrieve_sender_cert().await?;
			launch_repl(&mut app)?;
		},
		AuxinCommand::GetPayAddress(cmd) => {
			//Try converting our peer name into an AuxinAddress. 
			let recipient_addr = AuxinAddress::try_from(cmd.peer_name.as_str()).unwrap();
			let payment_address = app.retrieve_payment_address(&recipient_addr).await.unwrap();
			let payaddr_json = serde_json::to_string(&payment_address).unwrap();
			println!("{}", payaddr_json);
		},
	}
	app.state_manager.save_entire_context(&app.context).unwrap();
	Ok(())
}