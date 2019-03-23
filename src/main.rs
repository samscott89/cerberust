use krb5::buffer::Buffer;
use krb5::context::InitiateContext;
use krb5::kerberos::*;
use read_input::prelude::*;

fn main() {
	let config = GssClientConfig::new();
	let mut context = config.start_auth("server/krbtest.oso.dev").expect("could not start auth");
	
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

