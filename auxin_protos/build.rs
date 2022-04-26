fn main() {
	println!("cargo:rerun-if-changed=protos");

	let mut config = prost_build::Config::new();
	config.out_dir("src/generated/");

	config.compile_protos(&["protos/websocket.proto",
		"protos/signal_service.proto",
		"protos/sealed_sender.proto",
		"protos/storage.proto",
		"protos/groups.proto"], &["protos/"])
		.expect("Could not transpile protocol buffers into Rust files!");
}