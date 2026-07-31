use std::{
	net::{IpAddr, SocketAddr},
	str::FromStr as _,
	time::Duration,
};

use http::{HeaderMap, HeaderValue};
use log::*;
use reqwest::Url;

#[derive(clap::Parser)]
#[command(version = env!("REV"))]
pub struct Args {
	#[clap(short = 'l', long, default_value = "127.0.0.1:1053")]
	pub dns_listen: String,

	#[clap(short, long, default_value = "https://cloudflare-dns.com/dns-query")]
	pub upstream: String,

	/// set to "" to use system resolver for bootstrap resolving
	#[clap(short = 'a', long, default_value = "1.1.1.1,1.0.0.1")]
	pub upstream_addr: String,

	#[clap(short = 'b', long, default_value = "")]
	pub bind_addr: String,

	#[clap(short = 'i', long, default_value = "")]
	pub bind_interface: String,

	/// in milliseconds
	#[clap(short, long, default_value_t = 2501)]
	pub timeout: u16,

	/// polling interval for upstream address, in seconds
	#[clap(short, long, default_value_t = 2501)]
	pub poll_interval: u16,
}

const USER_AGENT: HeaderValue = HeaderValue::from_static("Naive DoH Proxy");
const APP_DNS_MSG: HeaderValue = HeaderValue::from_static("application/dns-message");

// since reqwest ClientBuilder is not clone-able and build is consuming
pub struct Conf {
	pub url: Url,
	pub addrs: Vec<SocketAddr>,
	headers: HeaderMap,
	bind_addr: Option<IpAddr>,
	bind_interface: String,
	timeout: Duration,
}

impl TryFrom<Args> for Conf {
	type Error = ();
	fn try_from(args: Args) -> Result<Self, Self::Error> {
		let url = Url::parse(&args.upstream)
			.map_err(|e| warn!("failed to parse \"{}\": {}", args.upstream, e))?;

		let mut addrs = Vec::with_capacity(2);
		if !args.upstream_addr.is_empty() {
			for a in args.upstream_addr.split(',') {
				let i = IpAddr::from_str(a)
					.map_err(|e| error!("error parsing address \"{a}\": {e}"))?;
				addrs.push(SocketAddr::new(i, 0));
			}
		}
		if addrs.is_empty() {
			warn!("using system resolver for bootstrapping");
		}

		let bind_addr =
			if args.bind_addr.is_empty() {
				None
			} else {
				Some(IpAddr::from_str(&args.bind_addr).map_err(|e| {
					error!("error parsing bind address \"{}\": {e}", args.bind_addr)
				})?)
			};

		let mut headers = HeaderMap::new();
		headers.insert(http::header::USER_AGENT, USER_AGENT);
		headers.insert(http::header::ACCEPT, APP_DNS_MSG);
		headers.insert(http::header::CONTENT_TYPE, APP_DNS_MSG);

		Ok(Self {
			url,
			addrs,
			headers,
			bind_addr,
			bind_interface: args.bind_interface,
			timeout: Duration::from_millis(args.timeout as u64),
		})
	}
}

impl Conf {
	pub fn build(&self) -> Result<reqwest::Client, ()> {
		let mut b = reqwest::ClientBuilder::new()
			.min_tls_version(reqwest::tls::Version::TLS_1_2)
			.connect_timeout(self.timeout)
			.read_timeout(self.timeout)
			.default_headers(self.headers.clone())
			.no_hickory_dns()
			.no_gzip()
			.no_deflate()
			.no_brotli()
			.no_zstd();
		#[cfg(any(target_os = "linux", target_os = "android"))]
		{
			b = b.tcp_user_timeout(self.timeout);
		}
		if !self.addrs.is_empty() {
			b = b.resolve_to_addrs(self.url.host_str().unwrap(), &self.addrs);
		}
		if let Some(a) = self.bind_addr {
			b = b.local_address(a);
		}
		if !self.bind_interface.is_empty() {
			b = b.interface(&self.bind_interface);
		}

		b.build()
			.map_err(|e| error!("failed to build reqwest client: {e}"))
	}
}
