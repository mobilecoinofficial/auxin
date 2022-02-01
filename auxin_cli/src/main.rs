// Copyright (c) 2021 MobileCoin Inc.
// Copyright (c) 2021 Emily Cultip

// Copyright (c) 2021 The MobileCoin Foundation
// Emily "Gyro" Cultip / The Forest team

//! Developer (and bot) friendly wrapper around the Signal protocol.

#![feature(async_closure)]
#![deny(bare_trait_objects)]

//Auxin dependencies

use auxin::{
	address::AuxinAddress,
	message::{MessageContent, MessageOut},
	state::AuxinStateManager,
	AuxinApp, AuxinConfig, ReceiveError, Result,
};

//External dependencies

use auxin_protos::WebSocketMessage;
use futures::executor::block_on;
use log::{debug, error, trace, warn};
use rand::rngs::OsRng;
use std::convert::TryFrom;
use structopt::StructOpt;
use tokio::{
	sync::{
		mpsc,
		mpsc::{Receiver, Sender},
	},
	task::JoinHandle,
	time::{Duration, Instant},
};
use tracing::{info, Level};
use tracing_futures::Instrument;
use tracing_subscriber::FmtSubscriber;

pub mod app;
pub mod attachment;
pub mod commands;
pub mod net;
pub mod repl_wrapper;
pub mod state;

// Dependencies from this crate.
use crate::initiate_attachment_downloads;
#[cfg(feature = "repl")]
use crate::repl_wrapper::AppWrapper;
pub use crate::{attachment::*, commands::*};
use auxin_protos::AttachmentPointer;
use net::{load_root_tls_cert, AuxinTungsteniteConnection};

pub type Context = auxin::AuxinContext;

pub static ATTACHMENT_TIMEOUT_DURATION: Duration = Duration::from_secs(48);

#[cfg(feature = "repl")]
pub fn launch_repl(app: &mut crate::app::App) -> Result<()> {
	use papyrus::repl;
	use std::path::Path;

	let mut app = AppWrapper { app_inner: app };

	let mut repl = repl!(AppWrapper);

	#[cfg(debug_assertions)]
	let library_dir = Path::new("target").join("debug");
	#[cfg(not(debug_assertions))]
	let library_dir = Path::new("target").join("release");

	let auxin_cli_lib = papyrus::linking::Extern::new(library_dir.join("libauxin_cli.rlib"))?;
	let auxin_lib = papyrus::linking::Extern::new(library_dir.join("libauxin.rlib"))?;
	let auxin_proto_lib = papyrus::linking::Extern::new(library_dir.join("libauxin_protos.rlib"))?;

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

pub fn main() {
	let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
	let runtime = tokio::runtime::Runtime::new().unwrap();
	std::thread::spawn(move || {
		tokio::runtime::Runtime::new()
			.unwrap()
			.block_on(async_main(tx))
			.unwrap();
	});
	match rx.blocking_recv() {
		Ok(code) => {
			runtime.shutdown_background();
			std::process::exit(code);
		}
		Err(x) => {
			println!("Error: {}", x);
			std::process::exit(1)
		}
	}
}

pub async fn async_main(exit_oneshot: tokio::sync::oneshot::Sender<i32>) -> Result<()> {
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

	let mut exit_code = 0;
	let arguments = AppArgs::from_args();

	let base_dir = format!("{}/data", arguments.config.as_str());
	debug!(
		"Using {} as the directory which holds our Signal protocol state.",
		base_dir
	);

	let mut config = AuxinConfig::default();
	let cert = load_root_tls_cert().unwrap();
	let net = crate::net::NetManager::new(cert);
	let state = crate::state::StateManager::new(&base_dir);

	config.enable_read_receipts = !arguments.no_read_receipt;
	// Get it to all come together.
	let mut app = AuxinApp::new(arguments.user.clone(), config, net, state, OsRng::default())
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

	#[allow(clippy::while_immutable_condition)]
	// TODO(Diana): Several match arms have a while loop with an exit condition that can never be false.
	// For now, suppress the error from Clippy.
	// TODO(Diana): A lot of `println`s in here. Should they be proper log macros?
	// Should find out.
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

			let json_attachment_pointer = serde_json::to_string(&attachments)?;
			println!("{}", json_attachment_pointer);

			info!(
				"Uploaded attachments in {} milliseconds.",
				start_time.elapsed().as_millis()
			);
		}
		AuxinCommand::ReceiveLoop => {
			let exit = false;
			let mut receiver =
				AuxinTungsteniteConnection::new(app.context.identity.clone()).await?;
			while !exit {
				while let Some(Ok(wsmessage)) = receiver.next().await {
					let msg_maybe = app.receive_and_acknowledge(&wsmessage).await?;

					if let Some(msg) = msg_maybe {
						let msg_json = serde_json::to_string(&msg).unwrap();
						println!("{}", msg_json);
					}
				}

				trace!("Entering sleep...");
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
			let mut receiver =
				AuxinTungsteniteConnection::new(app.context.identity.clone()).await?;
			while !exit {
				while let Some(msg) = receiver.next().await {
					match msg {
						Ok(wsmessage) => {
							let msg_maybe = app.receive_and_acknowledge(&wsmessage).await?;

							if let Some(msg) = msg_maybe {
								let msg_json = serde_json::to_string(&msg).unwrap();
								println!("{}", msg_json);

								if msg.content.receipt_message.is_none() {
									if let Some(st) = msg.content.text_message {
										info!("Message received with text \"{}\", replying...", st);
										app.send_message(
											&msg.remote_address.address,
											MessageOut {
												content: MessageContent::default()
													.with_text(st.clone()),
											},
										)
										.await
										.unwrap();
									}
								}
							}
						}
						Err(x) => println!("Error: {}", x),
					}
				}

				trace!("Entering sleep...");
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
			}
		}
		// Launch auxin as a json-rpc 2.0 daemon. Loops until killed or until method "exit" is called.
		AuxinCommand::JsonRPC => {
			// TODO: Permit people to configure receive behavior in the JsonRPC command,
			// including interval and whether or not to do receive ticks at all.
			let stdin = tokio::io::stdin();
			let reader = tokio::io::BufReader::new(stdin);
			let mut lines = tokio::io::AsyncBufReadExt::lines(reader);
			// JsonRPC never exits cleanly
			exit_code = 1;
			// --- SET UP OUR STDIN READER TASK

			//How many lines can we receive in one pass?
			const LINE_BUF_COUNT: usize = 4096;

			#[allow(clippy::type_complexity)]
			let (line_sender, mut line_receiver): (
				Sender<std::result::Result<String, std::io::Error>>,
				Receiver<std::result::Result<String, std::io::Error>>,
			) = mpsc::channel(LINE_BUF_COUNT);

			tokio::task::spawn_blocking(move || loop {
				// Poll stdin
				let maybe_input = block_on(lines.next_line());
				// What did we get back from stdin?
				match maybe_input {
					Ok(Some(input)) => {
						//Pass along a valid string.
						block_on(line_sender.send(Ok(input))).unwrap_or_else(|_| {
							panic!("Exceeded input buffer of {} lines", LINE_BUF_COUNT)
						});
					}
					Err(e) => {
						// Write a debug string of the error before the sender takes ownership of it.
						let err_string = format!("{:?}", &e);
						block_on(line_sender.send(std::result::Result::Err(e))).unwrap_or_else(
							|_| {
								panic!("Exceeded input buffer of {} lines, while attempting to return error: {:?}",
							LINE_BUF_COUNT, err_string)
							},
						);
					}
					// Ignore a None value, continuing to loop on this thread waiting for input.
					Ok(None) => {}
				}
			});

			// ---- SET UP OUR MAGIC MESSAGE RECEIVER

			let receiver_credentials = app.context.identity.clone();

			const MESSAGE_BUF_COUNT: usize = 4096;

			#[allow(clippy::type_complexity)]
			let (msg_channel, mut msg_receiver): (
				Sender<std::result::Result<WebSocketMessage, ReceiveError>>,
				Receiver<std::result::Result<WebSocketMessage, ReceiveError>>,
			) = mpsc::channel(MESSAGE_BUF_COUNT);

			tokio::task::spawn_blocking(move || {
				match block_on(AuxinTungsteniteConnection::new(receiver_credentials)) {
					Err(msg) => {
						println!("Failed to connect! {}", msg)
					}
					Ok(mut receiver) => {
						// once we've built: this will either receive forever, reconnect as needed, or die
						loop {
							while let Some(msg) = block_on(receiver.next()) {
								block_on(msg_channel.send(msg)).unwrap_or_else(|_| {
							panic!(
								"Unable to send incoming message to main auxin thread! It is possible you have exceeded the message buffer size, which is {}",
								MESSAGE_BUF_COUNT
							)
						});
							}
							trace!("Entering sleep...");
							let sleep_time = Duration::from_millis(100);
							block_on(tokio::time::sleep(sleep_time));

							if let Err(e) = block_on(receiver.refresh()) {
								log::warn!("Suppressing error on attempting to retrieve more messages - attempting to reconnect instead. Error was: {:?}", e);
								block_on(receiver.reconnect())
									.map_err(|e| ReceiveError::ReconnectErr(format!("{:?}", e)))
									.unwrap();
							}
						}
					}
				};
			});

			// Prepare to (potentially) download attachments
			//let mut pending_downloads: Vec<attachment::PendingDownload> = Vec::default();
			let mut download_task_handles: Vec<
				JoinHandle<std::result::Result<(), AttachmentPipelineError>>,
			> = Vec::default();

			let mut exit = false;
			// Infinite loop
			while !exit {
				// Receive first, attempting to ensure messages are read in the order they are sent.
				tokio::select! {
					biased;
					wsmessage_maybe = msg_receiver.recv() => {
						let mut attachments_to_download: Vec<AttachmentPointer> = Vec::default();
						if let Some(wsmessage_result) = wsmessage_maybe {
							match wsmessage_result {
								Ok(wsmessage) => {
									let message_maybe = app.receive_and_acknowledge(&wsmessage).await;
									match message_maybe {
										// If we actually got any messages this time we checked out mailbox, print them.
										Ok(Some(message)) => {
											attachments_to_download.extend_from_slice(&message.content.attachments);
											//Format our output as a JsonRPC notification.
											let notification = JsonRpcNotification {
												jsonrpc: String::from(commands::JSONRPC_VER),
												method: String::from("receive"),
												params: serde_json::to_value(message)?
											};
											//Perform some cleanup
											let message_value = serde_json::to_value(&notification)?;
											let cleaned_value = clean_json(&message_value)?;
											//Actually print our output!
											let message_json = serde_json::to_string(&cleaned_value)?;
											println!("{}", message_json);
											if !(attachments_to_download.is_empty()) {
												let message_downloads = initiate_attachment_downloads(
													attachments_to_download,
													arguments.download_path.to_str().unwrap().to_string(),
													app.get_http_client(),
													Some(ATTACHMENT_TIMEOUT_DURATION),
												);
												// Start our downloads.
												let handle = tokio::spawn(async move {
													// Transform Result<Vec<()>, E> to Result<(), E>
													futures::future::try_join_all(message_downloads.into_iter()).await.map(| _ | {})
												});
												// Make sure we do not forget the download - put the task on a list of tasks to
												// ensure we complete before exiting.
												download_task_handles.push(handle);
											};
										},
										Err(e) => {
											//Notify them of the error.
											let json_error = JsonRpcErrorResponse::from(e);
											let err_value = serde_json::to_value(&json_error)?;
											let cleaned_value = clean_json(&err_value)?;
											let resulting_error_json = serde_json::to_string(&cleaned_value)?;
											println!("{}", resulting_error_json);
										},
										Ok(None) => warn!("Recoverable error ignored in websocket message {:?}", &wsmessage),
									}
								},
								Err(e) => {
									let json_error = JsonRpcErrorResponse::from(e);
									let err_value = serde_json::to_value(&json_error)?;
									let cleaned_value = clean_json(&err_value)?;
									let resulting_error_json = serde_json::to_string(&cleaned_value)?;
									println!("{}", resulting_error_json);
								}
							}
						}
						else {
							error!("Message-receiver channel closed unexpectedly. Closing application.");
							exit = true;
						}
					}
					maybe_input = line_receiver.recv() => {
						// Convert Option<Result<T>> into Result<Option<T>>, then error check it to an Option<T>
						match maybe_input.transpose()? {
							Some(input) => {
								// A line of input has arrived!
								let output_list = process_jsonrpc_input(input.as_str(),
									&mut app, &arguments.download_path).await;
								for entry in output_list {
									// Convert to a json AST
									let result_val = match &entry {
										JsonRpcResponse::Ok(result) => serde_json::to_value(result),
										JsonRpcResponse::Err(result) => serde_json::to_value(result),
									}?;
									// Clean up our json structure for API compatibility with signal-cli.
									let cleaned_val = clean_json(&result_val)?;
									// Is this not just a null or an empty list?
									if let Some(inner_val) = cleaned_val {
										// Print it.
										let result_str = serde_json::to_string(&inner_val)?;
										println!("{}", result_str);
									}
									else {
										// Entire structure was empty.
										warn!("process_jsonrpc_input() produced an all-empty or all-null output, ignoring it. This was in response to: {}", &input);
									}
								}
							},
							None => {
								error!("Stdin line receiver channel closed unexpectedly. Closing application.");
								exit = true;
							},
						}
					}
				}
			}
			for handle in download_task_handles {
				//Ensure all downloads are completed.
				handle.await??;
			}
		}
		// Launches a read-evaluate-print loop, for experimentation in a development environment.
		// If the "repl" feature was not enabled when compiling this binary, this command will crash.
		AuxinCommand::Repl => {
			app.retrieve_sender_cert().await?;
			launch_repl(&mut app)?;
		}
		AuxinCommand::GetPayAddress(cmd) => {
			//Try converting our peer name into an AuxinAddress.
			let recipient_addr = AuxinAddress::try_from(cmd.peer_name.as_str()).unwrap();
			let payment_address = app.retrieve_payment_address(&recipient_addr).await.unwrap();
			let payaddr_json = serde_json::to_string(&payment_address).unwrap();
			println!("{}", payaddr_json);
		}
		AuxinCommand::SetProfile(cmd) => {
			let resp = handle_set_profile_command(cmd, &mut app).await?;
			println!(
				"Successfully updated Signal user profile! Http response was {:?}",
				resp
			);
		}
		AuxinCommand::GetProfile(cmd) => {
			let peername = cmd.peer_name.clone();
			let profile = handle_get_profile_command(cmd, &mut app).await?;
			let profile_json = serde_json::to_string(&profile)?;
			println!(
				"Retrieved profile for peer at address {}. Profile is: {}",
				peername, profile_json,
			)
		}
		AuxinCommand::Download(cmd) => {
			handle_download_command(cmd, &arguments.download_path, &mut app).await?;
			println!(
				"Attachment download to directory {:?} completed.",
				&arguments.download_path
			);
		}
	}
	app.state_manager.save_entire_context(&app.context).unwrap();
	let sleep_time = Duration::from_millis(100);
	block_on(tokio::time::sleep(sleep_time));

	exit_oneshot.send(exit_code).unwrap();
	Ok(())
}
