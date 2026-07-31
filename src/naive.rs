use std::{net::SocketAddr, rc::Rc};

use bytes::{Bytes, BytesMut};
use log::*;
use reqwest::Url;
use tokio::{net::UdpSocket, task, time::interval};

use super::Conf;

// reason for this is to make the ? short circuit work
// actual error handling is done locally in map_err
pub type Dummy = Result<(), ()>;

const RCV_BUF_LEN: usize = 0x600;

pub async fn naive(conf: Conf, s: UdpSocket) -> Dummy {
	let s = Rc::new(s);
	let client = conf.build()?;

	let mut buf = BytesMut::with_capacity(RCV_BUF_LEN);

	let mut poll = interval(conf.poll_interval);

	// to do: graceful shutdown?
	loop {
		tokio::select! {
			_ = poll.tick() => {
				debug!("poll tick");
			}
			r = s.recv_buf_from(&mut buf) => {
				match r {
					Ok((len, addr)) => {
						debug!("received {} bytes from {}", len, addr);
						let msg = buf.freeze();
						trace!("recv len: {}, msg len: {}", len, msg.len());
						task::spawn_local(proxy(conf.url.clone(), client.clone(), s.clone(), addr, msg));
						buf = BytesMut::with_capacity(RCV_BUF_LEN);
					}
					Err(e) => {
						warn!("udp recv err: {}", e);
					}
				}
			}
		}
	}
}

async fn exchange(url: Url, c: reqwest::Client, msg: Bytes) -> Result<Bytes, ()> {
	let res = c
		.request(reqwest::Method::POST, url)
		.header(http::header::CONTENT_LENGTH, msg.len())
		.body(msg)
		.send()
		.await
		.map_err(|e| warn!("failed to send request: {}", e))?;
	let status = res.status();
	#[cfg(debug_assertions)]
	for (n, v) in res.headers() {
		trace!("header dump - {}: {}", n, v.to_str().unwrap());
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

	res.bytes()
		.await
		.map_err(|e| warn!("error receiving DNS response from upstream: {}", e))
}

// to do: respond with error instead of let the client hanging
async fn proxy(
	url: Url,
	c: reqwest::Client,
	s: Rc<UdpSocket>,
	addr: SocketAddr,
	msg: Bytes,
) -> Dummy {
	let msg = exchange(url, c, msg).await?;

	info!(
		"received {} bytes from upstream, sending it back to {}",
		msg.len(),
		addr
	);
	s.send_to(&msg, addr)
		.await
		.map_err(|e| warn!("error sending DNS response back to {}: {}", addr, e))?;

	Ok(())
}
