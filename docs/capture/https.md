# HTTPS diagnostics

NetStat opens reports from a local explicit mitmproxy session. Configure
one compatible client to use the proxy and trust its session CA. The recorder
limits forwarding and recording to the selected host and port. The client
name is a manual label. HTTP/1.x and HTTP/2 go through the TCP proxy.
QUIC and HTTP/3 are outside this mode.

From the NetStat directory, with mitmdump and Python installed:

```sh
python tools/https_capture.py example.com --client curl
```

On Termux with `grun`, pass `--glibc --mitmdump /path/to/linux-arm64/mitmdump`
to use the standalone binary. See the [Termux commands](https.ru.md#запуск-в-termux)
and [mitmproxy installation guide](https://docs.mitmproxy.org/stable/overview/installation/).

The script prints the proxy address, scope and public CA certificate path.
In a second terminal, substitute that path for a one-request trust scope:

```sh
curl --noproxy "" --proxy http://127.0.0.1:8080 --cacert '/path/to/mitmproxy-ca-cert.pem' https://example.com/
```

The proxy validates the upstream certificate. Clients with their own certificate
policies may reject the connection. The report shows observed TLS failures.
[Explicit proxy mode](https://docs.mitmproxy.org/stable/concepts/modes/) ·
[Certificate setup](https://docs.mitmproxy.org/stable/concepts/certificates/)

Stop with Ctrl+C or wait for the session deadline, three minutes by default.
The script removes the temporary CA directory and prints the local report path.
In NetStat open **Capture → HTTPS → Open diagnostic session**, or send the private
file directly from Termux:

```sh
termux-open --send --chooser --content-type application/vnd.netstat.https+json '/path/to/session.netstat-https.json'
```

Select NetStat in the chooser. Search covers URLs, headers and decoded body
previews. The recorder caps each preview at 256 KiB and stream-forwards larger
bodies. NetStat reads the report into memory until you leave the screen. Remove
the client's temporary proxy and trust settings, and delete the report after
use. It may contain tokens and request data.
