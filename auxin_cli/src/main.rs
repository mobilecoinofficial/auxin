#![feature(async_closure)]

use std::cell::RefCell;
use std::convert::TryFrom;
use std::time::Duration;

use auxin::address::AuxinAddress;
use auxin::message::{MessageContent, MessageOut};
use auxin::state::AuxinStateManager;
use auxin::{AuxinApp, AuxinConfig, AuxinReceiver, ReceiveError};
use auxin::{Result};
use log::info;
use rand::rngs::OsRng;

use clap::{App, Arg, SubCommand};

pub mod state;
pub mod net;

use net::load_root_tls_cert;
use crate::net::NetManager;
use crate::state::*;

pub type Context = auxin::AuxinContext;

#[tokio::main]
pub async fn main() -> Result<()> {

	const AUTHOR_STR: &str = "Millie C. <gyrocoder@gmail.com>";
	const VERSION_STR: &str = "PRE-RELEASE DO NOT USE";

	let args = App::new("auxin-cli")
						.version(VERSION_STR)
						.author(AUTHOR_STR)
						.about("[TODO]")
						.arg(Arg::with_name("VERBOSE")
							.short("v")
							.long("verbose")
							.value_name("PHONE_NUMBER")
							.required(false)
							.takes_value(false)
							.help("Print logs to stderr (verbosely)"))
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
							.author(AUTHOR_STR))
						.get_matches();

	let our_phone_number = args.value_of("USER")
		.expect("Must select a user ID! Input either your UUID or your phone number (in E164 format, i.e. +[country code][phone number]");
	let our_phone_number = our_phone_number.to_string();

	simple_logger::SimpleLogger::new().with_level(log::LevelFilter::Debug).init().unwrap();

    let base_dir = "state/data/";
	let cert = load_root_tls_cert().unwrap();
	let net = NetManager::new(cert);
	let state = StateManager::new(base_dir);
	// Get it to all come together.
	let mut app = AuxinApp::new(our_phone_number, AuxinConfig{ }, net, state, OsRng::default()).await.unwrap();

	if let Some(send_command) = args.subcommand_matches("send") { 
		let dest = send_command.value_of("DESTINATION").unwrap();
		let recipient_addr = AuxinAddress::try_from(dest).unwrap();

		let message_text = send_command.value_of("MESSAGE").unwrap();
		let message_content = MessageContent::default().with_text(message_text.to_string());
		let message = MessageOut {
			content: message_content,
		};

		app.send_message(&recipient_addr, message).await.unwrap();
	}

	if let Some(payaddr_command) = args.subcommand_matches("getpayaddress") { 
		let dest = payaddr_command.value_of("PEER").unwrap();
		let recipient_addr = AuxinAddress::try_from(dest).unwrap();
		let payment_address = app.retrieve_payment_address(&recipient_addr).await.unwrap();
		let payaddr_json = serde_json::to_string(&payment_address).unwrap();
		
		println!("[PAYMENT_ADDRESS]");
		println!("{}",  payaddr_json);
	}

	if let Some(_) = args.subcommand_matches("receive") { 
		let mut receiver = AuxinReceiver::new(&mut app).await.unwrap();
		while let Some(msg) = receiver.next().await {
			let msg = msg.unwrap();
			if let Some(msg) = &msg.content.text_message {
				info!("Message received with text {}", msg);
			}
			let msg_json = serde_json::to_string_pretty(&msg).unwrap();
			println!("[MESSAGE]");
			println!("{}",  msg_json);
		}
	}

	if let Some(_) = args.subcommand_matches("echoserver") { 
		let mut exit = false;
		// Ugly hack to get around the multiple ways the borrow checker doesn't recognize what we're trying to do.
		let receiver_main = RefCell::new( Some( AuxinReceiver::new(&mut app).await.unwrap() ));
		while !exit {
			let receiver = receiver_main.take();
			let mut receiver = receiver.unwrap();
			while let Some(msg) = receiver.next().await {
				let msg = msg.unwrap();

				let msg_json = serde_json::to_string_pretty(&msg).unwrap();
				println!("[MESSAGE]");
				println!("{}",  msg_json);

				if let Some(st) = msg.content.text_message {
					if st.eq_ignore_ascii_case("/stop") {
						exit = true;
					}
					else {
						info!("Message received with text \"{}\", replying...", st);
						receiver.send_message(&msg.remote_address.address, MessageOut{ content: MessageContent::default().with_text(st.clone()) }).await.unwrap();
					}
				}
			}
			
			let sleep_time = Duration::from_millis(100);
			tokio::time::sleep(sleep_time).await;
			
			if let Err(e) = receiver.refresh().await {
				log::warn!("Suppressing error on attempting to retrieve more messages - attempting to reconnect instead. Error was: {:?}", e);
				receiver.reconnect().await.map_err(|e| ReceiveError::ReconnectErr(format!("{:?}", e))).unwrap();
			}
			
			receiver_main.replace(Some(receiver));
		}
	}
	app.state_manager.save_entire_context(&app.context).unwrap();
	
    Ok(())
}