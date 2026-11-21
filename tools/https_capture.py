"""Start an explicit loopback HTTPS diagnostic proxy for one host and port."""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile

PREVIEW = 256 * 1024
MAX_FLOWS = 512
MAX_EXPORT = 7 * 1024 * 1024
DNS_NAME = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class Recorder:
    def __init__(self, host, port, client, output):
        self.host = host
        self.port = port
        self.output = output
        self.entries = {}
        self.size = 0
        self.client_handshakes = set()
        self.established_without_http = set()
        self.report = dict(format="netstat-https", version=1, client=client, host=host, port=port,
                           clientTlsFailures=0, clientTlsWithoutHttp=0, serverTlsFailures=0, limited=False)

    def allows(self, host, port):
        return host is not None and host.lower() == self.host and port == self.port

    @staticmethod
    def message(message):
        headers = [[key, value] for key, value in message.headers.items(multi=True)]
        if (len(headers) > 128 or any(len(key) > 256 or len(value) > 32768 for key, value in headers)
                or sum(len(key) + len(value) for key, value in headers) > 32768):
            return None
        body = message.raw_content
        return dict(version=message.http_version, headers=headers,
                    body=base64.b64encode((body or b"")[:PREVIEW]).decode("ascii"),
                    size=len(body or b""), previewMissing=body is None)

    def record(self, flow):
        request = flow.request
        if not self.allows(request.host, request.port) or request.scheme != "https":
            return
        if self.report["limited"]:
            return
        if ((len(self.entries) == MAX_FLOWS and flow.id not in self.entries)
                or len(request.url) > 8192 or len(request.method) > 64):
            self.report["limited"] = True
            return
        first = self.message(request)
        second = self.message(flow.response) if flow.response else None
        if first is None or (flow.response is not None and second is None):
            self.report["limited"] = True
            return
        first.update(method=request.method, url=request.url)
        entry = dict(id=flow.id, request=first)
        if second is not None:
            second["status"] = flow.response.status_code
            entry["response"] = second
        encoded = json.dumps(entry, ensure_ascii=True, separators=(",", ":"))
        old = self.entries.get(flow.id, "")
        if self.size - len(old) + len(encoded) > MAX_EXPORT:
            self.report["limited"] = True
            return
        self.entries[flow.id] = encoded
        self.size += len(encoded) - len(old)

    def done(self):
        pending = self.output.with_suffix(".tmp")
        # Only one finalized file is exposed to the user.
        with pending.open("x", encoding="utf-8") as file:
            file.write(json.dumps(self.report)[:-1])
            file.write(',"flows":[')
            file.write(",".join(self.entries.values()))
            file.write("]}\n")
        pending.replace(self.output)


def addon():
    from mitmproxy import http

    class NetStatRecorder(Recorder):
        def http_connect(self, flow):
            if not self.allows(flow.request.host, flow.request.port):
                flow.response = http.Response.make(403)

        def server_connect(self, data):
            if data.server.address is None or not self.allows(*data.server.address):
                data.server.error = "Outside the NetStat diagnostic scope"

        def requestheaders(self, flow):
            self.established_without_http.discard(flow.client_conn.id)
            request = flow.request
            if request.scheme != "https" or not self.allows(request.host, request.port):
                flow.response = http.Response.make(403)
                return
            # Save the request early so a shutdown or upstream failure leaves a partial exchange.
            self.record(flow)

        def request(self, flow):
            self.record(flow)

        def response(self, flow):
            self.record(flow)

        def error(self, flow):
            self.record(flow)

        def tls_clienthello(self, event):
            self.client_handshakes.add(event.context.client.id)

        def tls_established_client(self, event):
            self.client_handshakes.discard(event.conn.id)
            self.established_without_http.add(event.conn.id)

        def tls_failed_client(self, event):
            self.fail_handshake(event.conn.id)

        def client_disconnected(self, client):
            self.fail_handshake(client.id)
            if client.id in self.established_without_http:
                self.established_without_http.remove(client.id)
                self.report["clientTlsWithoutHttp"] += 1

        def fail_handshake(self, client_id):
            # Some clients close the socket without sending a fatal TLS alert.
            if client_id in self.client_handshakes:
                self.client_handshakes.remove(client_id)
                self.report["clientTlsFailures"] += 1

        def tls_failed_server(self, _event):
            self.report["serverTlsFailures"] += 1

    return NetStatRecorder(os.environ["NETSTAT_HTTPS_HOST"], int(os.environ["NETSTAT_HTTPS_PORT"]),
                           os.environ["NETSTAT_HTTPS_CLIENT"], Path(os.environ["NETSTAT_HTTPS_OUTPUT"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="one DNS hostname")
    parser.add_argument("--client", required=True, help="name of the client configured for this session")
    parser.add_argument("--port", default=443, type=int, help="HTTPS port on the server")
    parser.add_argument("--listen-port", default=8080, type=int)
    parser.add_argument("--seconds", default=180, type=int)
    parser.add_argument("--directory", type=Path, help="new private directory for the session")
    parser.add_argument("--mitmdump", default="mitmdump", help="path to an installed mitmdump")
    parser.add_argument("--glibc", action="store_true", help="run the Linux binary with Termux grun")
    options = parser.parse_args()
    host = options.host.lower()
    if not DNS_NAME.fullmatch(host):
        parser.error("provide one DNS hostname without a scheme, wildcard or path")
    if not 1 <= len(options.client.strip()) <= 120:
        parser.error("provide a client name of up to 120 characters")
    if not 1 <= options.seconds <= 300 or not 1 <= options.port <= 65535 or not 1024 <= options.listen_port <= 65535:
        parser.error("invalid duration or port")

    binary = shutil.which(options.mitmdump)
    if binary is None:
        parser.error("mitmdump is required and was not found")
    command_prefix = [binary]
    if options.glibc:
        grun = shutil.which("grun")
        if grun is None:
            parser.error("Termux grun was not found")
        command_prefix.insert(0, grun)
    os.umask(0o077)
    directory = options.directory or Path(tempfile.mkdtemp(prefix="netstat-https-"))
    if options.directory:
        directory.mkdir(mode=0o700)
    if stat.S_IMODE(directory.stat().st_mode) & 0o077:
        parser.error("choose a private directory inside Termux or the current user home")
    output = directory.resolve() / "session.netstat-https.json"
    env = dict(os.environ, NETSTAT_HTTPS_HOST=host, NETSTAT_HTTPS_PORT=str(options.port),
               NETSTAT_HTTPS_CLIENT=options.client.strip(), NETSTAT_HTTPS_OUTPUT=str(output))
    with tempfile.TemporaryDirectory(prefix="ca-", dir=directory) as ca:
        command = command_prefix + ["--mode", "regular", "--listen-host", "127.0.0.1",
                   "--listen-port", str(options.listen_port), "--set", f"confdir={Path(ca).resolve()}",
                   "--set", "ssl_insecure=false", "--set", "connection_strategy=lazy",
                   "--set", "http3=false", "--set", "stream_large_bodies=256k",
                   "--set", "flow_detail=0", "--set", "termlog_verbosity=warn",
                   "-s", str(Path(__file__).resolve())]
        print(f"{options.client} • https://{host}:{options.port} • 127.0.0.1:{options.listen_port}", flush=True)
        print(f"Client CA certificate: {Path(ca).resolve() / 'mitmproxy-ca-cert.pem'}", flush=True)
        print(f"Stop with Ctrl+C or wait {options.seconds} seconds.", flush=True)
        with subprocess.Popen(command, env=env, start_new_session=True) as process:
            try:
                process.wait(timeout=options.seconds)
            except (KeyboardInterrupt, subprocess.TimeoutExpired):
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    if not output.is_file():
        parser.exit(1, "No session file was saved. Check the mitmdump output.\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
elif "NETSTAT_HTTPS_OUTPUT" in os.environ:
    addons = [addon()]
