fn main() {
	std::env::set_var("OUT_DIR", "src/");
	println!("cargo:rerun-if-changed=protos");
	prost_build::compile_protos(&["protos/websocket.proto",
		"protos/signal_service.proto",
		"protos/sealed_sender.proto",
		"protos/storage.proto",
		"protos/groups.proto"], &["protos/"])
		.expect("Could not transpile protocol buffers into Rust files!");
}