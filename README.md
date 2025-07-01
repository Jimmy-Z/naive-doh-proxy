### naive DNS-over-HTTPS proxy
naive as in it is entirely oblivious to the DNS message format,
and treat it as a black box.

### under the hood
* it simply exchanges DNS messages between UDP and HTTPS using MIME type `application/dns-message`.
* HTTPS is handled by reqwest.

### why?
since lots of tools doesn't support DoH.
