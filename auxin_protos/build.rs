use protobuf_codegen_pure::Customize;

extern crate protobuf_codegen_pure;

fn main() {
	println!("cargo:rerun-if-changed=protos");
	protobuf_codegen_pure::Codegen::new()
		.out_dir("src/protos")
		.inputs(&["protos/websocket.proto"])
		.inputs(&["protos/signalservice.proto"])
		.inputs(&["protos/sealed_sender.proto"])
		.inputs(&["protos/storage.proto"])
		.inputs(&["protos/groups.proto"])
		.inputs(&["protos/decrypted_groups.proto"])
		.customize(Customize {
			gen_mod_rs: Some(true),
			serde_derive: Some(true),
			..Default::default()
		})
		.include("protos")
		.run()
		.expect("Codegen failed.");
}
