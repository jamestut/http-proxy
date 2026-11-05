# HTTP proxy

HTTP Proxy forwards HTTP requests and TCP CONNECT tunnels directly or through named HTTP proxies. Destination rules select the route. HTTPS proxy connections can use HTTP/2 and multiplex tunnels over one connection.

The repository also provides `reverse-proxy` and `agent` for networks where the upstream side must initiate the connection. The reverse proxy accepts normal proxy clients, and an agent connects to it and routes traffic using the same rules as the standard proxy.

## Get started

Go 1.26 or later is required. Build the program on macOS or Linux:

```sh
go build -o http-proxy ./src
```

Copy [examples/config.example.json](examples/config.example.json) and edit `config.json` for your setup:

```sh
cp examples/config.example.json config.json
```

Replace the example credentials and upstream address before use. The proxy settings belong in the `proxy` object. To connect directly without an upstream, remove its `upstreams`, `defaults`, and `domain` sections.

Start the proxy:

```sh
./http-proxy run --config config.json
```

Run `./http-proxy version` to show version, build, and source information.

The default bind is `127.0.0.1` and the default port is `8080`. Set `--bind` and `--port` separately to change them. Use `--bind all` to listen on all interfaces. The wildcard addresses `0.0.0.0` and `::` also normally listen on both IPv4 and IPv6 interfaces when the system supports dual-stack sockets. The proxy fails to start if it cannot bind the port. You can pass a specific IPv6 address such as `::1` without brackets. The short forms are `-b` for `--bind`, `-p` for `--port`, and `-c` for `--config`. Configure a client to use the proxy's address and port and enter the configured username and password. For example, replace the credentials in this command with your own:

```sh
curl --proxy http://127.0.0.1:8080 --proxy-user alice:example-password https://example.com/
```

Omit `proxy.auth` to accept requests without authentication. Credentials on a plain HTTP proxy connection are exposed to the network, and the server warns when authentication is enabled without HTTPS. Usernames must contain only lowercase ASCII letters and digits. Passwords must be nonempty UTF-8 strings without control characters and may contain colons. Some clients and upstream proxies may not support non-ASCII passwords.

## Reverse proxy and agent

Build the other programs and prepare their configuration:

```sh
go build -o reverse-proxy ./cmd/reverse-proxy
go build -o agent ./cmd/agent
cp examples/reverse-proxy.example.json reverse-proxy.json
cp examples/agent.example.json agent.json
```

Configure `agent_listener.cert` and `agent_listener.key` with a certificate and key for the address the agent uses. Replace the example passwords and `agent.address`, and make the agent credentials match one of the reverse proxy's named upstreams. The example binds the agent listener to all interfaces. Choose a reachable address for your network. Set `client_listen` independently for normal proxy clients.

Start the reverse proxy and agent on their respective machines:

```sh
./reverse-proxy run --config reverse-proxy.json
./agent run --config agent.json
```

Configure clients to use the reverse proxy's client listener. The reverse proxy applies its routing rules first. A selected agent then applies its own routing rules, which may connect directly or use a standard HTTP proxy. The example agent connects directly. Put standard upstreams and routing rules inside its `proxy` object using the same format as the `proxy` object in [examples/config.example.json](examples/config.example.json). An agent does not accept independent proxy clients, so do not configure downstream `auth` or listener TLS certificates in its `proxy` object.

The agent validates the reverse proxy certificate against the system trust store. For a private CA, set `agent.ca` to its PEM file. To connect through an HTTP CONNECT proxy, set `agent.proxy_url` to an HTTP proxy URL such as `http://proxy.example.net:3128`. The URL may include Basic credentials. Relative certificate and CA paths are resolved from the respective configuration file's directory. The agent listener always uses HTTPS and HTTP/2. Set `proxy.tls.cert` and `proxy.tls.key` separately if clients should use HTTPS on the client listener.

Each reverse upstream requires unique Basic credentials and does not have a `host` field. An agent authenticates with those credentials when it connects. Only one agent is active per upstream. A newly authenticated agent replaces the old one and asks it to exit, ending its active tunnels. Run the agent under a service manager configured to restart it after a crash or kill, but not after a successful exit. A selected upstream that has no agent fails the request without falling back to a direct connection.

Reload the reverse proxy or agent using the same configuration path used to start it:

```sh
./reverse-proxy reload --config reverse-proxy.json
./agent reload --config agent.json
```

Changing agent credentials on the reverse proxy does not disconnect a healthy agent. The agent must use the new credentials when it reconnects. Removing an upstream asks its agent to exit. Agent routing changes apply to new requests, while changes to its connection settings apply at the next reconnect. Existing tunnels retain their routing settings. Changing listener addresses or switching the client listener between HTTP and HTTPS requires restarting the reverse proxy. Updated certificates apply to new TLS connections.

The agent settings `connect_timeout`, `retry_delay`, `ping_idle`, and `ping_timeout` accept Go duration strings such as `5s`. Their defaults are `30s`, `5s`, `30s`, and `15s`. The reverse proxy's `agent_listener` accepts `ping_idle`, `ping_timeout`, and `shutdown_timeout`, with defaults of `30s`, `15s`, and `5s`. Health check changes apply to new agent connections. The shutdown timeout limits how long the proxy waits for a replaced or removed agent to close its connection.

## HTTPS and HTTP/2

Add a `tls` section inside `proxy` to serve HTTPS and offer HTTP/2 via TLS ALPN on the standalone proxy or reverse proxy client listener:

```json
{
  "proxy": {
    "tls": {
      "cert": "server.crt",
      "key": "server.key"
    }
  }
}
```

`cert` and `key` must be supplied together. Configure clients to trust the server certificate. The optional `proxy.tls.upstream_ca` adds certificates to the system trust pool for HTTPS upstream proxies. It can be supplied without a server certificate, including in an agent's `proxy` object. Relative TLS paths are resolved from the configuration file's directory. HTTPS upstream connections negotiate HTTP/2 when supported and otherwise use HTTP/1.1. Cleartext connections use HTTP/1.1.

HTTP/2 CONNECT supports client-side half-close. If the target closes its write side first, the proxy closes the HTTP/2 tunnel instead of keeping the client-to-target side open. Use HTTP/1.1 for protocols that require the target to half-close first and continue receiving data.

## Routing

The routing settings below belong in the `proxy` object. For the standalone proxy and agent, upstream `host` values are `http://` or `https://` proxy URLs. Their `auth` section is optional and uses the same Basic credential rules as downstream authentication. A selected upstream receives a CONNECT request for each target. Upstream failures return an error to the client without falling back to a direct connection. Reverse proxy upstreams identify agents instead, as described above.

The `defaults.ip`, `defaults.domain`, and `defaults.unqualified-domain` values name an upstream or are `null`. Omitted defaults are `null`. IP rules support IPv4 and IPv6 CIDRs and choose the longest matching prefix. Domain rules choose the most specific match. An exact name matches only that name, while `*.example.com` matches subdomains but not `example.com` itself. Matching is case-insensitive and ignores a trailing dot.

Scoped IPv6 destinations, such as `fe80::1%eth0`, are not supported in client requests.

For an IP destination, `null` means connect directly. For a domain destination, `null` means resolve it locally and apply the IP rules and IP default to the results. A selected domain upstream receives the hostname without local resolution. An unqualified domain is a name without a dot, such as `localhost`.

## Reload configuration

Edit the same config file and run:

```sh
./http-proxy reload
```

Pass the same `--bind` and `--port` values used by `run` if they differ from the defaults. For example, use `./http-proxy reload --bind all --port 8080` to reload an instance started with those values. The server validates the complete replacement before applying it. An invalid replacement leaves the active configuration unchanged. New HTTP requests and HTTP/2 streams use the new configuration, and existing tunnels continue with their original settings. Updated server certificates and upstream CA settings apply to new TLS connections. Switching a listener between HTTP and HTTPS requires a restart.

The per-user control socket and instance lock live under `$XDG_RUNTIME_DIR/http-proxy/`, or `os.TempDir()/http-proxy-<UID>/` when `XDG_RUNTIME_DIR` is unset. The directory is private to the user, and each bind and port pair has its own socket and lock.

## Development

Build all three programs for macOS ARM64, Linux ARM64, and Linux x64 with:

```sh
./build.sh
```

The script writes nine binaries to `dist/` and disables CGO for cross-compilation. These binaries use Go's DNS resolver, which can differ from the system resolver on some networks.

The build script embeds the current tag or commit and the build time. A regular `go build` reports `dev` and an unknown build time, while Go's source metadata is available when the build environment supports it.

Run the test suite with:

```sh
go test ./...
```
