# HTTP proxy

HTTP Proxy forwards HTTP requests and TCP CONNECT tunnels directly or through named HTTP proxies. Destination rules select the route. HTTPS proxy connections can use HTTP/2 and multiplex tunnels over one connection.

## Get started

Go 1.26 or later is required. Build the program on macOS or Linux:

```sh
go build -o http-proxy ./src
```

Copy [config.example.json](config.example.json) and edit `config.json` for your setup:

```sh
cp config.example.json config.json
```

Replace the example credentials and upstream address before use. To connect directly without an upstream, remove the `upstreams`, `defaults`, and `domain` sections.

Start the proxy:

```sh
./http-proxy run --config config.json
```

Run `./http-proxy version` to show version, build, and source information.

The default bind is `127.0.0.1` and the default port is `8080`. Set `--bind` and `--port` separately to change them. Use `--bind all` to listen on all interfaces. The wildcard addresses `0.0.0.0` and `::` also normally listen on both IPv4 and IPv6 interfaces when the system supports dual-stack sockets. The proxy fails to start if it cannot bind the port. You can pass a specific IPv6 address such as `::1` without brackets. The short forms are `-b` for `--bind`, `-p` for `--port`, and `-c` for `--config`. Configure a client to use the proxy's address and port and enter the configured username and password. For example, replace the credentials in this command with your own:

```sh
curl --proxy http://127.0.0.1:8080 --proxy-user alice:example-password https://example.com/
```

Omit `auth` to accept requests without authentication. Credentials on a plain HTTP proxy connection are exposed to the network, and the server warns when authentication is enabled without HTTPS. Usernames must contain only lowercase ASCII letters and digits. Passwords must be nonempty UTF-8 strings without control characters and may contain colons. Some clients and upstream proxies may not support non-ASCII passwords.

## HTTPS and HTTP/2

Add a `tls` section to serve HTTPS and offer HTTP/2 via TLS ALPN:

```json
{
  "tls": {
    "cert": "server.crt",
    "key": "server.key",
    "upstream_ca": "upstream-ca.crt"
  }
}
```

`cert` and `key` must be supplied together. Configure clients to trust the server certificate. The optional `upstream_ca` adds certificates to the system trust pool for HTTPS upstream proxies. It can be supplied without a server certificate. Relative TLS paths are resolved from the configuration file's directory. HTTPS upstream connections negotiate HTTP/2 when supported and otherwise use HTTP/1.1. Cleartext connections use HTTP/1.1.

HTTP/2 CONNECT supports client-side half-close. If the target closes its write side first, the proxy closes the HTTP/2 tunnel instead of keeping the client-to-target side open. Use HTTP/1.1 for protocols that require the target to half-close first and continue receiving data.

## Routing

Upstream `host` values are `http://` or `https://` proxy URLs. Their `auth` section is optional and uses the same Basic credential rules as downstream authentication. A selected upstream receives a CONNECT request for each target. Upstream failures return an error to the client without falling back to a direct connection.

The `defaults.ip`, `defaults.domain`, and `defaults.unqualified-domain` values name an upstream or are `null`. Omitted defaults are `null`. IP rules support IPv4 and IPv6 CIDRs and choose the longest matching prefix. Domain rules choose the most specific match. An exact name matches only that name, while `*.example.com` matches subdomains but not `example.com` itself. Matching is case-insensitive and ignores a trailing dot.

For an IP destination, `null` means connect directly. For a domain destination, `null` means resolve it locally and apply the IP rules and IP default to the results. A selected domain upstream receives the hostname without local resolution. An unqualified domain is a name without a dot, such as `localhost`.

## Reload configuration

Edit the same config file and run:

```sh
./http-proxy reload
```

Pass the same `--bind` and `--port` values used by `run` if they differ from the defaults. For example, use `./http-proxy reload --bind all --port 8080` to reload an instance started with those values. The server validates the complete replacement before applying it. An invalid replacement leaves the active configuration unchanged. New HTTP requests and HTTP/2 streams use the new configuration, and existing tunnels continue with their original settings. Updated server certificates and upstream CA settings apply to new TLS connections. Switching a listener between HTTP and HTTPS requires a restart.

The per-user control socket and instance lock live under `$XDG_RUNTIME_DIR/http-proxy/`, or `os.TempDir()/http-proxy-<UID>/` when `XDG_RUNTIME_DIR` is unset. The directory is private to the user, and each bind and port pair has its own socket and lock.

## Development

Build release binaries for macOS ARM64, Linux ARM64, and Linux x64 with:

```sh
./build.sh
```

The script writes the binaries to `dist/` and disables CGO for cross-compilation. These binaries use Go's DNS resolver, which can differ from the system resolver on some networks.

The build script embeds the current tag or commit and the build time. A regular `go build` reports `dev` and an unknown build time, while Go's source metadata is available when the build environment supports it.

Run the test suite with:

```sh
go test ./...
```
