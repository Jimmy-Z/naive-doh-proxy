use std::
	net::SocketAddr
;

use clap::Parser;
use log::*;

use tokio::{net::UdpSocket, task};

mod conf;
mod naive;
use conf::*;
use naive::*;

#[cfg(debug_assertions)]
const DEFAULT_LOG_LEVEL: &str = "debug";
#[cfg(not(debug_assertions))]
const DEFAULT_LOG_LEVEL: &str = "info";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Dummy {
	let args = conf::Args::parse();

	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(DEFAULT_LOG_LEVEL))
		.init();

	let addr: SocketAddr = args
		.dns_listen
		.parse()
		.map_err(|e| error!("failed to parse address \"{}\": {}", args.dns_listen, e))?;
	debug!("trying to listen on {}", addr);
	let s = UdpSocket::bind(addr)
		.await
		.map_err(|e| error!("failed to bind address {}: {}", addr, e))?;
	// I wonder how could this fail though
	match s.local_addr() {
		Ok(a) => info!("listening on {}", a),
		Err(e) => error!("failed to get local address from listening socket: {}", e),
	}

	let conf = Conf::try_from(args)?;

	// localSet to allow !Send in async
	let local = task::LocalSet::new();
	let _ = local.run_until(naive(conf, s)).await;
	local.await;

	Ok(())
}
