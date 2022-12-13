# ctrld
A highly configurable DNS forwarding proxy with support for:
- Multiple listeners for incoming queries
- Multiple upstreams with fallbacks
- Multiple network policy driven DNS query steering
- Policy driven domain based "split horizon" DNS with wildcard support

All DNS protocols are supported, including:
- `UDP 53`
- `DNS-over-HTTPS`
- `DNS-over-TLS`
- `DNS-over-HTTP/3` (DOH3)
- `DNS-over-QUIC`

## Use Cases
1. Use secure DNS protocols on networks and devices that don't natively support them (legacy routers, legacy OSes, TVs, smart toasters).
2. Create source IP based DNS routing policies with variable secure DNS upstreams. Subnet 1 (admin) uses upstream resolver A, while Subnet 2 (employee) uses upstream resolver B.
3. Create destination IP based DNS routing policies with variable secure DNS upstreams. Listener 1 uses upstream resolver C, while Listener 2 uses upstream resolver D.
4. Create domain level "split horizon" DNS routing policies to send internal domains (*.company.int) to a local DNS server, while everything else goes to another upstream.


## OS Support
- Windows (386, amd64, arm)
- Mac (amd64, arm64)
- Linux (386, amd64, arm, mips)

## Download
Download pre-compiled binaries from the [Releases](https://github.com/Control-D-Inc/ctrld/releases) section.

## Build
`ctrld` requires `go1.19+`:

```shell
$ go build ./cmd/ctrld
```

or

```shell
$ go install github.com/Control-D-Inc/ctrld/cmd/ctrld@latest
```

## Arguments
```
Usage:
  ctrld [command]

Available Commands:
  help        Help about any command
  run         Run the DNS proxy server

Flags:
  -h, --help      help for ctrld
  -v, --verbose   verbose log output
      --version   version for ctrld

Use "ctrld [command] --help" for more information about a command.
```

## Usage
To start the server with default configuration, simply run: `ctrld run`. This will create a generic `config.toml` file in the working directory and start the service.
1. Start the server
  ```
  $ sudo ./ctrld run
  ```

2. Run a test query using a DNS client, for example, `dig`:
  ```
  $ dig verify.controld.com @127.0.0.1 +short
  api.controld.com.
  147.185.34.1
  ```

If `verify.controld.com` resolves, you're successfully using the default Control D upstream.


## Configuration
### Example
- Start `listener.0` on 127.0.0.1:53
- Accept queries from any source address
- Send all queries to `upstream.0` via DoH protocol

### Default Config
```toml
[listener]

  [listener.0]
    ip = "127.0.0.1"
    port = 53
    restricted = false

[network]

  [network.0]
    cidrs = ["0.0.0.0/0"]
    name = "Network 0"

[service]
  log_level = "info"
  log_path = ""

[upstream]

  [upstream.0]
    bootstrap_ip = "76.76.2.11"
    endpoint = "https://freedns.controld.com/p1"
    name = "Control D - Anti-Malware"
    timeout = 5000
    type = "doh"

  [upstream.1]
    bootstrap_ip = "76.76.2.11"
    endpoint = "p2.freedns.controld.com"
    name = "Control D - No Ads"
    timeout = 3000
    type = "doq"

```

### Advanced
The above is the most basic example, which will work out of the box. If you're looking to do advanced configurations using policies, see [Configuration Docs](docs/config.md) for complete documentation of the config file.

## Contributing

See [Contribution Guideline](./docs/contributing.md)

## Roadmap
The following functionality is on the roadmap and will be available in future releases.
- Prometheus metrics exporter
- Local caching
- Service self-installation
