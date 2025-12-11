use crate::envelope::Envelope;
use serde_cbor::Value;
use std::collections::HashMap;

pub type TypeId = u64;

pub struct TypedRouter {
	handlers: HashMap<TypeId, Box<dyn Fn(&Envelope) -> Option<Envelope> + Send + Sync>>,
}

impl TypedRouter {
	pub fn new() -> Self {
		Self { handlers: HashMap::new() }
	}

	pub fn on<F>(&mut self, type_id: TypeId, f: F)
	where
		F: Fn(&Envelope) -> Option<Envelope> + Send + Sync + 'static,
	{
		self.handlers.insert(type_id, Box::new(f));
	}

	pub fn route(&self, env: &Envelope) -> Option<Envelope> {
		self.handlers.get(&env.type_id).and_then(|f| f(env))
	}
}

pub fn make_request(type_id: TypeId, msg_ver: u64, payload: Value) -> Envelope {
	Envelope::new(type_id, msg_ver, payload)
}

pub fn make_response_for(req: &Envelope, type_id: TypeId, msg_ver: u64, payload: Value) -> Envelope {
	let mut resp = Envelope::new(type_id, msg_ver, payload);
	let mut corr = [0u8;16];
	corr.copy_from_slice(&req.msg_id);
	resp = resp.with_corr(corr);
	resp
}


