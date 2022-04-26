fn main() {
	std::env::set_var("OUT_DIR", "src/protos");
	println!("cargo:rerun-if-changed=protos");
	prost_build::compile_protos(&["protos/websocket.proto",
		"protos/signalservice.proto",
		"protos/sealed_sender.proto",
		"protos/storage.proto",
		"protos/groups.proto"], &["protos/"])
		.expect("Could not transpile protocol buffers into Rust files!");
}