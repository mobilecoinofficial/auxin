// Copyright (c) 2021 MobileCoin Inc.
// Copyright (c) 2021 Emily Cultip

// Copyright (c) 2021 The MobileCoin Foundation
// Emily "Gyro" Cultip / The Forest team

//! Developer (and bot) friendly wrapper around the Signal protocol.

#![feature(async_closure)]
#![feature(path_file_prefix)]
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
use libsignal_protocol::KeyPair;
use log::{debug, error, trace};
use rand::{rngs::OsRng, CryptoRng, Rng};
use reqwest::{header, StatusCode};
use std::{collections::HashMap, convert::TryFrom};
use structopt::StructOpt;
use tokio::{
	sync::{
		mpsc,
		mpsc::{Receiver, Sender},
	},
	task::JoinHandle,
	time::{interval_at, Duration, Instant},
};
use tracing::{info, warn, Level};
use tracing_futures::Instrument;
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

pub mod app;
pub mod attachment;
pub mod commands;
pub mod net;
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

pub fn main() {
	// used to send the exit code from async_main to the main task
	let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
	// async_main never returns because stdin blocking task never exits
	std::thread::spawn(move || {
		tokio::runtime::Runtime::new()
			.unwrap()
			.block_on(async_main(tx))
			.unwrap();
	});
	// so we just run async_main in its own thread and do a blocking_recv call on the exit pipe
	let exit_code = rx.blocking_recv();
	// we sleep a bit so all the Drop()s get a chance to run (re-flushing keystate)
	let sleep_time = Duration::from_millis(1000);
	std::thread::sleep(sleep_time);
	match exit_code {
		Ok(code) => {
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


	#[cfg(not(git_untracked))]
	warn!("Could not determine if this build has been modified from the source repository. Please ensure build.rs is being run correctly.");

	/*-----------------------------------------------\\
	||------------ INIT CONTEXT/IDENTITY ------------||
	\\-----------------------------------------------*/

	let mut exit_code = 0;
	let arguments = AppArgs::from_args();

	debug!(
		"Using {} as the directory which holds our Signal protocol state.",
		arguments.config
	);

	let mut config = AuxinConfig::default();
	let cert = load_root_tls_cert().unwrap();
	let net = crate::net::NetManager::new(cert);
	let state = crate::state::StateManager::new(&arguments.config);

	config.enable_read_receipts = !arguments.no_read_receipt;

	{
		/// A signal account "password"
		///
		/// 18 random bytes, base64 encoded
		#[derive(Debug, serde::Serialize, serde::Deserialize)]
		struct Password(String);
		impl Password {
			/// Generate a new password
			///
			/// Should only be called once at registration
			pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
				// Signal generates a 18 byte random password at registration
				// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/registration/viewmodel/RegistrationViewModel.java#L42
				Self(base64::encode(rng.gen::<[u8; 18]>()))
			}

			/// Base64 encoded password
			pub fn password(&self) -> &str {
				&self.0
			}
		}

		/// A 32-byte 256-bit profile key
		#[derive(Debug, serde::Serialize, serde::Deserialize)]
		struct ProfileKey([u8; 32]);
		impl ProfileKey {
			/// Generate a profile key
			///
			/// Should only be called once at registration
			pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
				// Signal generates a 32 byte random key at registration
				// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/crypto/ProfileKeyUtil.java#L75
				// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/registration/RegistrationRepository.java#L81
				Self(rng.gen())
			}

			pub fn key(&self) -> &[u8; 32] {
				&self.0
			}
		}

		/// E164 formatted phone number
		#[derive(Debug, serde::Serialize, serde::Deserialize)]
		struct PhoneNumber(String);

		impl PhoneNumber {
			fn new(phone: impl Into<String>) -> Self {
				Self(phone.into())
			}

			fn phone(&self) -> &str {
				&self.0
			}
		}

		/// Represents the state we are required to keep for our own user account
		#[derive(Debug, serde::Serialize, serde::Deserialize)]
		struct SignalAccount<Rng> {
			rng: Rng,

			/// Phone number
			phone: PhoneNumber,

			/// ACI
			account_identity: Option<Uuid>,

			/// PNI
			phone_identity: Option<Uuid>,

			/// Registration ID
			reg_id: i32,

			/// Profile Key
			profile_key: ProfileKey,

			/// Randomly generated "password"
			password: Password,

			/// All our prekeys and their IDs
			// NOTE: Signal-android for some reason generates 2^24-1 bit IDs
			prekeys: HashMap<u32, String>,
		}

		impl<R: Rng + CryptoRng> SignalAccount<R> {
			/// Create a new signal account
			pub fn new(phone: impl Into<String>, mut rng: R) -> Self {
				Self {
					prekeys: HashMap::new(),
					password: dbg!(Password::generate(&mut rng)),
					phone: PhoneNumber::new(phone),
					account_identity: None,
					phone_identity: None,
					// See https://github.com/signalapp/libsignal-client/blob/6787408e5d8fc8e60c92e43cb0cee3dd6d2c8640/java/shared/java/org/whispersystems/libsignal/util/KeyHelper.java#L41
					// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/registration/RegistrationRepository.java#L68-L75
					reg_id: rng.gen_range(1, 16380),
					// As a new account we won't have an existing profile key, so make one
					profile_key: ProfileKey::generate(&mut rng),
					rng,
				}
			}

			/// Register a signal account with the server
			///
			/// `code` is the verification code from SMS verification.
			pub async fn register_sms(
				phone: impl Into<String>,
				code: impl Into<String>,
				rng: R,
			) -> Result<Self> {
				todo!()
			}

			pub fn set_aci(&mut self, aci: Uuid) {
				let _ = self.account_identity.insert(aci);
				let keys = KeyPair::generate(&mut self.rng);
			}
		}

		impl<R> SignalAccount<R> {
			pub fn auth_token(&self) -> String {
				// If no ACI, such as during registering, uses the phone number
				// See
				// https://github.com/signalapp/Signal-Android/blob/v5.33.3/libsignal/service/src/main/java/org/whispersystems/signalservice/internal/push/PushServiceSocket.java#L1794
				// https://github.com/signalapp/Signal-Android/blob/v5.33.3/libsignal/service/src/main/java/org/whispersystems/signalservice/internal/push/PushServiceSocket.java#L2129
				match self.account_identity {
					Some(aci) => base64::encode(format!("{}:{}", &aci, self.password.password())),
					None => base64::encode(format!(
						"{}:{}",
						&self.phone.phone(),
						self.password.password()
					)),
				}
			}

			pub fn registration_id(&self) -> i32 {
				self.reg_id
			}

			pub fn profile_key(&self) -> &[u8] {
				self.profile_key.key()
			}
		}

		//
		let account = SignalAccount::new(&arguments.user, rand::thread_rng());
		//
		let mut rng = rand::thread_rng();
		let mut headers = header::HeaderMap::new();
		headers.insert(
			"X-Signal-Agent",
			header::HeaderValue::from_static(auxin::net::USER_AGENT),
		);
		headers.insert(
			"Authorization",
			header::HeaderValue::from_str(&format!("Basic {}", account.auth_token()))?,
		);
		dbg!(&headers);
		let cert = reqwest::Certificate::from_pem(auxin::SIGNAL_TLS_CERT.as_bytes())?;
		let client = reqwest::ClientBuilder::new()
			.add_root_certificate(cert)
			.tls_built_in_root_certs(false)
			.default_headers(headers)
			.user_agent(auxin::net::USER_AGENT)
			.build()?;
		// TODO(Diana): Probably get a cryptographer to review before we use this?
		// Since we/i generate our own keys and give them to signal?
		match &arguments.command {
			AuxinCommand::Register { captcha } => {
				let url = match captcha {
					Some(c) => format!(
						"https://chat.signal.org/v1/accounts/sms/code/{}?client=android&captcha={c}",
						arguments.user,
					),
					None => format!(
						"https://chat.signal.org/v1/accounts/sms/code/{}?client=android",
						arguments.user,
					),
				};
				let res = client.get(url).send().await?;
				let status = res.status();
				let body = res.bytes().await?;
				match status {
					StatusCode::BAD_REQUEST => {
						if body.is_empty() {
							error!("Impossible phone number?");
							return Err("Impossible phone number".into());
						}
					}
					// Captcha Required
					StatusCode::PAYMENT_REQUIRED => {
						error!("Captcha required. Re-run auxin-cli with a captcha from https://signalcaptchas.org/challenge/generate.html");
						return Err("Captcha Required".into());
					}
					StatusCode::OK => (),
					c => warn!("Received unknown response from signal servers: {c}"),
				}
				return Ok(());
			}
			AuxinCommand::Verify { code } => {
				let url = format!("https://chat.signal.org/v1/accounts/code/{}", code);
				dbg!(&code);
				// TODO(Diana): registration lock code 423

				// See [`auxin::context::get_unidentified_access_for_key`]
				// https://github.com/signalapp/Signal-Android/blob/v5.33.5/app/src/main/java/org/thoughtcrime/securesms/registration/VerifyAccountRepository.kt#L56
				// https://github.com/signalapp/Signal-Android/blob/v5.33.3/libsignal/service/src/main/java/org/whispersystems/signalservice/api/crypto/UnidentifiedAccess.java#L40-L55
				let unidentified_access = {
					use aes_gcm::{
						aead::{Aead, NewAead},
						Aes256Gcm, Key, Nonce,
					};
					let profile_key = Key::from_slice(&account.profile_key());
					// panic!("UGH");
					let cipher = Aes256Gcm::new(profile_key);
					let nonce = Nonce::from_slice(&[0u8; 12]);

					// Signal trims this to 16 bytes?
					&cipher.encrypt(nonce, &[0u8; 16][..])?[..16]
				};

				let json = serde_json::json! {{
					// Next few are hard-coded to null
					// https://github.com/signalapp/Signal-Android/blob/v5.33.3/libsignal/service/src/main/java/org/whispersystems/signalservice/api/SignalServiceAccountManager.java#L285
					"signalingKey": null,
					"pin": null,
					"name": null,
					// Only for new registrations
					// TODO(Diana): Support registration lock
					"registrationLock": null,

					// Hard-coded to true
					// https://github.com/signalapp/Signal-Android/blob/v5.33.3/libsignal/service/src/main/java/org/whispersystems/signalservice/api/account/AccountAttributes.java#L63
					"voice": true,
					"video": true,

					// This is true if FCM(Firebase Cloud Messaging) is *not* being used.
					// For us that probably means this should always be true.
					"fetchesMessages": true,

					// Access key? base64-encoded
					"unidentifiedAccessKey": base64::encode(&unidentified_access),

					// Hard-coded/defaults to false?
					"unrestrictedUnidentifiedAccess": false,

					// Currently soft-coded to true by feature flags
					// Presumably will change at some point
					//
					// https://github.com/signalapp/Signal-Android/blob/v5.33.5/app/src/main/java/org/thoughtcrime/securesms/registration/VerifyAccountRepository.kt#L73
					// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/keyvalue/PhoneNumberPrivacyValues.java#L47-L50
					"discoverableByPhoneNumber": true,

					// Hard coded
					// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/AppCapabilities.java
					"capabilities": {
						"uuid": true,
						"storage": false,
						"senderKey": true,
						"announcementGroup": true,
						"changeNumber": true,
						"gv2-3": true,
						"gv1-migration": true
					},

					// Random 14-bit?? number unique to this signal install
					// "Should" remain consistent across registrations
					"registrationId": account.registration_id()
				}};
				// let json = serde_json::to_string(&json)?;
				let req = dbg!(client.put(url).json(&json)).build()?;
				dbg!(req.headers());
				let res = client.execute(req).await?;
				dbg!(&res);
				let status = res.status();
				dbg!(&status);
				match status {
					StatusCode::OK => {
						// Returns our UUID/ACI and UUID/PNI from the server
						let json: serde_json::Value = res.json().await?;
						dbg!(&json);

						// On registration, after getting the ACI/PNI
						// Signal generates an identity keypair for both
						//
						// See
						// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/dependencies/ApplicationDependencyProvider.java#L287-L309
						// and
						// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/registration/RegistrationRepository.java#L131-L140
						let aci = json["uuid"].as_str().unwrap();
						let aci_identity_pair = KeyPair::generate(&mut rng);

						let pni = json["pni"].as_str().unwrap();
						let pni_identity_pair = KeyPair::generate(&mut rng);

						// Signal then generates a keypair for the prekeys
						// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/keyvalue/AccountValues.kt#L223-L230
						let signed_prekey_id: i32 = rng.gen_range(0, 0xFFFFFF);
						let signed_prekey = KeyPair::generate(&mut rng);

						// And a signature, from our ACI identity.
						let message = signed_prekey.public_key.public_key_bytes()?;
						let sig = aci_identity_pair.calculate_signature(message, &mut rng)?;

						// From this point on, next ACI signed_prekey ID is as follows
						// (signed_prekey_id + 1) % 0xFFFFFF
						// See
						// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/crypto/PreKeyUtil.java#L76

						// See https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/crypto/PreKeyUtil.java#L50
						let prekey_id_offset: i32 = rng.gen_range(0, 0xFFFFFF);
						let mut prekeys = Vec::new();
						for i in 0..100 {
							let prekey_id = (prekey_id_offset + i) % 0xFFFFFF;
							let prekey_pair = KeyPair::generate(&mut rng);
							let p = prekey_pair.public_key.public_key_bytes()?;

							// prekeys.push((prekey_id, base64::encode(p)));
							// prekeys((prekey_id, base64::encode(p)));
							let j = serde_json::json! {{
								"keyId": prekey_id,
								"publicKey": base64::encode(p)
							}};
							prekeys.push(j);
						}
						// Next ACI pre_key IDs are as follows
						// (prekey_id_offset + 100 + 1) % 0xFFFFFF

						// And sends it all to the server
						let json = serde_json::json! {{
							"identityKey": base64::encode(aci_identity_pair.public_key.public_key_bytes()?),
							"preKeys": [
								prekeys
							],
							"signedPreKey": {
								"keyId": signed_prekey_id,
								"publicKey": base64::encode(message),
								"signature": base64::encode(sig)
							}
						}};
						let url = "https://chat.signal.org/v2/keys/?identity=aci";
						let _res = client
							.put(url)
							.bearer_auth(account.auth_token())
							.json(&json)
							.send()
							.await?;
					}
					StatusCode::INTERNAL_SERVER_ERROR
					| StatusCode::FORBIDDEN
					| StatusCode::UNAUTHORIZED => {
						error!("Invalid SMS code, cannot verify");
						return Err("Invalid SMS code, cannot verify".into());
					}
					c => warn!("Received unknown response from signal servers: {c}"),
				}
				return Ok(());
			}
			_ => (),
		}
	}

	// Get it to all come together.
	let mut app = AuxinApp::new(arguments.user.clone(), config, net, state, OsRng::default())
		.instrument(tracing::info_span!("AuxinApp"))
		.await?;

	/*-----------------------------------------------\\
	||--------------- COMMAND DISPATCH --------------||
	\\-----------------------------------------------*/

	// This is the only place commands which initiate an infinite loop or otherwise
	// take over program flow are handled. Anything which should not be available
	// within json-rpc (including the command to start a json-rpc daemon) goes here.
	// As of 0.1.13, that is Echoserver and JsonRPC.

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

			let (do_send_ping_in, mut do_send_ping_out): (Sender<bool>, Receiver<bool>) =
				mpsc::channel(1);

			// blocking task which polls stdin and sends lines to be processed
			tokio::task::spawn_blocking(move || loop {
				// TODO: add a oneshot here and select across lines.next_line and the oneshot rx,
				// send a message to trigger this task's termination
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

			const MESSAGE_BUF_COUNT: usize = 8192;

			// channel that forwards websocket messages and errors to be handled
			#[allow(clippy::type_complexity)]
			let (msg_channel, mut msg_receiver): (
				Sender<std::result::Result<WebSocketMessage, ReceiveError>>,
				Receiver<std::result::Result<WebSocketMessage, ReceiveError>>,
			) = mpsc::channel(MESSAGE_BUF_COUNT);

			// task that triggers pings, running in its own happy little sleep environment
			tokio::task::spawn(async move {
				// trigger a PING every 55s
				let mut interval = interval_at(Instant::now(), Duration::from_secs(55));
				loop {
					interval.tick().await;
					do_send_ping_in.send(true).await.unwrap();
				}
			});

			// selects forever over either a new websocket message or a pending ping
			tokio::task::spawn(async move {
				let mut interval = interval_at(Instant::now(), Duration::from_millis(50));
				match AuxinTungsteniteConnection::new(receiver_credentials).await {
					Err(msg) => {
						println!("Failed to connect! {}", msg)
					}
					// once we've built receiver: this will either receive forever, reconnect as needed, or die
					Ok(mut receiver) => {
						loop {
							tokio::select! {
									biased;
								   _ =  interval.tick() => {} // seemingly needed to jigger the selector at 20Hz
									Some(msg) = receiver.next() =>  { // forward it along or panic!
										msg_channel.send(msg).await.unwrap_or_else(|_| {
									panic!(
										"Unable to send incoming message to main auxin thread! It is possible you have exceeded the message buffer size, which is {}",
										MESSAGE_BUF_COUNT
									)
								});
									}
								_ = do_send_ping_out.recv() => { // do ping and reconnect if necessary
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
		AuxinCommand::GetUuid(cmd) => {
			let phone_number = cmd.peer.clone();
			let output = handle_get_uuid_command(cmd, &mut app).await;
			match output {
				Ok(uuid) => {
					println!("Uuid for user {} is {}", phone_number, uuid);
				}
				Err(e) => {
					println!("Could not get a UUID for the provided peer due to the following error: {:?}", e);
				}
			}
		}
		_ => unreachable!(),
	}
	app.state_manager.save_entire_context(&app.context).unwrap();
	println!("finished syncing context");
	exit_oneshot.send(exit_code).unwrap();
	Ok(())
}
