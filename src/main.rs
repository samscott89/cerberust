use krb5::buffer::Buffer;
use krb5::context::{AcceptContext, InitiateContext};
use krb5::kerberos::*;
use read_input::prelude::*;

fn main() {
	let config = GssConfig::new();
	let mut context = config.init_auth("server/localhost").expect("could not start auth");
	let mut server_context = config.accept_auth("server/localhost").expect("could not start auth");
	
	let mut buffer = Buffer::new();
	let mut res = context.step(buffer);
	println!("Got first client token: {:?}", res);
	while let Some(b) = res.expect("failed to step") {
		let sr = server_context.step(b).expect("failed to step");
		println!("Processed server side");
		if let Some(buf) = sr {
			println!("Challenge for client");
			res = context.step(buf)
		} else {
			println!("Server returned nothing");
			// panic!("Server returned nothing");
			res = Ok(None);
		}
	}
	println!("Finished doing auth");
	match (context, server_context) {
		(InitiateContext::Continue { .. }, _) => panic!("Client wants to continue but no buffer returned"),
		(_, AcceptContext::Continue { ..}) => panic!("Server wants to continue but client finished"),
		(InitiateContext::Done { context }, AcceptContext::Done { context: server_context }) => {
			println!("Client info: {:#?}", context.get_info());
			println!("Server info: {:#?}", server_context.get_info());
		}
	}
}


fn client_main() {
	let config = GssConfig::new();
	let mut context = config.init_auth("server/krbtest.oso.dev").expect("could not start auth");
	
	let mut buffer = Buffer::new();
	let mut res = context.step(buffer);
	while let Some(b) = res.expect("failed to step") {
		let input: String = input().msg(format!("Output: {:?}\n Enter response from server:", b.as_base64())).get();
		println!("Input token: {:?}", input);
		let buffer = Buffer::from_base64(&input).expect("invalid return token");
		res = context.step(buffer);
		println!("Step...");
	}
	println!("Finished doing auth");
	match context {
		InitiateContext::Continue { .. } => panic!("Client wants to continue but no buffer returned"),
		InitiateContext::Done { context } => {
			println!("Info: {:#?}", context.get_info());
		}
	}
}

