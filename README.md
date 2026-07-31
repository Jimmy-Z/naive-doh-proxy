### naive DNS-over-HTTPS proxy
naive as in it is entirely oblivious to the DNS message format,
and treat it as a black box.

### under the hood
* it simply exchanges DNS messages between UDP and HTTPS using MIME type `application/dns-message`.
* HTTPS is handled by reqwest.

### why?
* since lots of tools doesn't support DoH.
	* there's https-dns-proxy, used in openwrt, but not packaged for debian
		* naive is probably not better than it
	* there's dnscrypt-proxy, but it's go
* dig requires HTTP/2, naive doesn't enforce this.
