#![feature(async_closure)]

use std::convert::TryFrom;

use auxin::address::AuxinAddress;
use auxin::message::{MessageContent, MessageOut};
use auxin::state::AuxinStateManager;
use auxin::{AuxinApp, AuxinConfig, AuxinReceiver};
use auxin::{Result};
use log::{LevelFilter, info};
use rand::rngs::OsRng;
use simple_logger::SimpleLogger;

use clap::{App, Arg, SubCommand};

pub mod state;
pub mod net;

use net::load_root_tls_cert;
use crate::net::NetManager;
use crate::state::*;

pub type Context = auxin::AuxinContext;

#[tokio::main]
pub async fn main() -> Result<()> {
	SimpleLogger::new()
		.with_level(LevelFilter::Info)
		.init()
		.unwrap();
	const AUTHOR_STR: &str = "Millie C. <gyrocoder@gmail.com>";
	const VERSION_STR: &str = "PRE-RELEASE DO NOT USE";

	let args = App::new("auxin-cli")
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
						.subcommand(SubCommand::with_name("send")
							.about("Sends a message to the specified address.")
							.version(VERSION_STR)
							.author(AUTHOR_STR)
							.args_from_usage("<DESTINATION> 'Sets the destination for our message'")
							.arg(Arg::with_name("MESSAGE")
								.short("m")
								.long("message")
								.value_name("MESSAGE_BODY")
								.required(true)
								.takes_value(true)
								.help("Determines the message text we will send."))
						).subcommand(SubCommand::with_name("receive")
							.about("Polls for incoming messages.")
							.version(VERSION_STR)
							.author(AUTHOR_STR)
						).subcommand(SubCommand::with_name("echoserver")
							.about("A simple echo server for demonstration purposes.")
							.version(VERSION_STR)
							.author(AUTHOR_STR))
						.get_matches();

	let our_phone_number = args.value_of("USER")
		.expect("Must select a user ID! Input either your UUID or your phone number (in E164 format, i.e. +[country code][phone number]");
	let our_phone_number = our_phone_number.to_string();

    let base_dir = "state/data/";

	let cert = load_root_tls_cert()?;

	let net = NetManager::new(cert);
	let state = StateManager::new(base_dir);
	// Get it to all come together.
	let mut app = AuxinApp::new(our_phone_number, AuxinConfig{ }, net, state, OsRng::default()).await?;

	if let Some(send_command) = args.subcommand_matches("send") { 
		let dest = send_command.value_of("DESTINATION").unwrap();
		let recipient_addr = AuxinAddress::try_from(dest)?;

		let message_text = send_command.value_of("MESSAGE").unwrap();
		let message_content = MessageContent::TextMessage(message_text.to_string());
		let message = MessageOut {
			content: message_content,
		};

		app.send_message(&recipient_addr, message).await?;
	}

	if let Some(_) = args.subcommand_matches("receive") { 
		let mut receiver = AuxinReceiver::new(&mut app).await?;
		while let Some(msg) = receiver.next().await {
			let msg = msg?;
			println!("{:?}", msg);
			match msg.content {
				MessageContent::TextMessage(msg) => info!("Message received with text {}", msg),
				MessageContent::ReceiptMessage(_, _) => {},
				MessageContent::Other(_) => {},
			}
		}
	}

	if let Some(_) = args.subcommand_matches("echoserver") { 
		let mut exit = false;
		while !exit {
			let mut receiver = AuxinReceiver::new(&mut app).await?;
			while let Some(msg) = receiver.next().await {
				let msg = msg?;
				match msg.content {
					MessageContent::TextMessage(st) => {

						if st.eq_ignore_ascii_case("/quit") {
							exit = true;
						}
						else {
							//info!("Message received with text {}, replying...", st);
							receiver.send_message(&msg.remote_address.address, MessageOut{ content: MessageContent::TextMessage(st.clone()) }).await?;
						}
					},
					_ => {},
				}
			}
		}
	}
	app.state_manager.save_entire_context(&app.context)?;
	
    Ok(())
}