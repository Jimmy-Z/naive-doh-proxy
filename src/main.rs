use std::{
	net::{IpAddr, SocketAddr},
	rc::Rc,
	time::Duration,
};

use clap::Parser;
use http::{HeaderMap, HeaderValue};
use log::*;

use tokio::{net::UdpSocket, task};

// reason for this is to make the ? short circuit work
// actual error handling is done locally in map_err
type Result = std::result::Result<(), ()>;

const USER_AGENT: HeaderValue = HeaderValue::from_static("Naive DoH Proxy");
const APP_DNS_MSG: HeaderValue = HeaderValue::from_static("application/dns-message");

#[derive(clap::Parser)]
struct Args {
	#[clap(short = 'l', long, default_value = "127.0.0.1:1053")]
	pub dns_listen: String,

	#[clap(short, long, default_value = "cloudflare-dns.com")]
	pub upstream_host: String,

	/// set to "" to let reqwest handle bootstrap resolving
	#[clap(short = 'a', long, default_value = "1.1.1.1,1.0.0.1")]
	pub upstream_addr: String,

	#[clap(long, default_value_t = 443)]
	pub upstream_port: u16,

	#[clap(long, default_value = "/dns-query")]
	pub upstream_path: String,
}

#[cfg(debug_assertions)]
const DEFAULT_LOG_LEVEL: &str = "debug";
#[cfg(not(debug_assertions))]
const DEFAULT_LOG_LEVEL: &str = "info";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result {
	let a = Args::parse();

	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(DEFAULT_LOG_LEVEL))
		.init();

	let addr: SocketAddr = a
		.dns_listen
		.parse()
		.map_err(|e| error!("failed to parse address \"{}\": {}", a.dns_listen, e))?;
	debug!("trying to listen on {}", addr);
	let s = UdpSocket::bind(addr)
		.await
		.map_err(|e| error!("failed to bind address {}: {}", addr, e))?;
	// I wonder how could this fail though
	match s.local_addr() {
		Ok(a) => info!("listening on {}", a.to_string()),
		Err(e) => error!("failed to get local address from listening socket: {}", e),
	}

	let mut headers = HeaderMap::new();
	headers.insert(http::header::USER_AGENT, USER_AGENT);
	headers.insert(http::header::ACCEPT, APP_DNS_MSG);
	headers.insert(http::header::CONTENT_TYPE, APP_DNS_MSG);

	let mut c = reqwest::ClientBuilder::new()
		.min_tls_version(reqwest::tls::Version::TLS_1_2)
		.connect_timeout(Duration::from_millis(2501))
		.read_timeout(Duration::from_millis(2501))
		.tcp_user_timeout(Duration::from_millis(2501))
		.default_headers(headers)
		.no_hickory_dns()
		.no_gzip()
		.no_deflate()
		.no_brotli()
		.no_zstd();

	if a.upstream_addr.len() > 0 {
		let upstream_addrs: Vec<SocketAddr> = a
			.upstream_addr
			.split(',')
			.filter_map(|a| {
				a.parse::<IpAddr>()
					.map_err(|e| error!("failed to parse address \"{}\": {}", a, e))
					.ok()
			})
			.map(|ip_addr| SocketAddr::new(ip_addr, a.upstream_port))
			.collect();
		if upstream_addrs.len() > 0 {
			c = c.resolve_to_addrs(&a.upstream_host, &upstream_addrs);
		} else {
			warn!("fallback to use system DNS to handle bootstrapping");
		}
	}

	let c = c
		.build()
		.map_err(|e| error!("failed to build reqwest client: {}", e))?;

	// localSet to allow !Send in async
	let local = task::LocalSet::new();
	local.run_until(naive(a, c, s)).await;
	local.await;

	Ok(())
}

async fn naive(a: Args, c: reqwest::Client, s: UdpSocket) {
	let a = Rc::new(a);
	let s = Rc::new(s);

	let mut buf = vec![0u8; 0x600];

	// to do: graceful shutdown?
	loop {
		let r = s.recv_from(&mut buf).await;
		match r {
			Ok((len, addr)) => {
				info!("received {} bytes from {}", len, addr);
				task::spawn_local(fire(
					a.clone(),
					c.clone(),
					s.clone(),
					addr,
					buf[..len].to_vec(),
				));
			}
			Err(e) => {
				warn!("udp recv err: {}", e);
			}
		}
	}
}

// to do: respond with error instead of let the client hanging
async fn fire(
	a: Rc<Args>,
	c: reqwest::Client,
	s: Rc<UdpSocket>,
	addr: SocketAddr,
	msg: Vec<u8>,
) -> Result {
	let res = c
		.request(
			reqwest::Method::POST,
			format!("https://{}{}", a.upstream_host, a.upstream_path),
		)
		.header(http::header::CONTENT_LENGTH, msg.len())
		.body(msg)
		.send()
		.await
		.map_err(|e| warn!("failed to send request: {}", e))?;
	let status = res.status();
	#[cfg(debug_assertions)]
	for (n, v) in res.headers() {
		trace!("header dump - {}: {}", n.to_string(), v.to_str().unwrap());
	}
	if status != http::StatusCode::OK {
		warn!("upstream returned {}:", status);
		let text = res
			.text()
			.await
			.map_err(|e| warn!("\n failed to decoding text from upstream: {}", e))?;
		warn!("\t{}\n", text);
		return Err(());
	}

	let msg = res
		.bytes()
		.await
		.map_err(|e| warn!("error receiving DNS response from upstream: {}", e))?;

	info!("received {} bytes from upstream, sending it back to {}", msg.len(), addr);
	s.send_to(&msg, addr)
		.await
		.map_err(|e| warn!("error sending DNS response back to {}: {}", addr, e))?;

	Ok(())
}
