# ctrld

![Test](https://github.com/Control-D-Inc/ctrld/actions/workflows/ci.yml/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/Control-D-Inc/ctrld.svg)](https://pkg.go.dev/github.com/Control-D-Inc/ctrld)
[![Go Report Card](https://goreportcard.com/badge/github.com/Control-D-Inc/ctrld)](https://goreportcard.com/report/github.com/Control-D-Inc/ctrld)

![ctrld spash image](/docs/ctrldsplash.png)

A highly configurable DNS forwarding proxy with support for:
- Multiple listeners for incoming queries
- Multiple upstreams with fallbacks
- Multiple network policy driven DNS query steering
- Policy driven domain based "split horizon" DNS with wildcard support
- Integrations with common router vendors and firmware
- LAN client discovery via DHCP, mDNS, ARP, NDP, hosts file parsing
- Prometheus metrics exporter 

## TLDR
Proxy legacy DNS traffic to secure DNS upstreams in highly configurable ways. 

All DNS protocols are supported, including:
- `UDP 53`
- `DNS-over-HTTPS`
- `DNS-over-TLS`
- `DNS-over-HTTP/3` (DOH3)
- `DNS-over-QUIC`

# Use Cases
1. Use secure DNS protocols on networks and devices that don't natively support them (legacy routers, legacy OSes, TVs, smart toasters).
2. Create source IP based DNS routing policies with variable secure DNS upstreams. Subnet 1 (admin) uses upstream resolver A, while Subnet 2 (employee) uses upstream resolver B.
3. Create destination IP based DNS routing policies with variable secure DNS upstreams. Listener 1 uses upstream resolver C, while Listener 2 uses upstream resolver D.
4. Create domain level "split horizon" DNS routing policies to send internal domains (*.company.int) to a local DNS server, while everything else goes to another upstream.
5. Deploy on a router and create LAN client specific DNS routing policies from a web GUI (When using ControlD.com).


## OS Support
- Windows (386, amd64, arm)
- Mac (amd64, arm64)
- Linux (386, amd64, arm, mips)
- FreeBSD
- Common routers (See Router Mode below)

# Install
There are several ways to download and install `ctrld`.

## Quick Install
The simplest way to download and install `ctrld` is to use the following installer command on any UNIX-like platform:

```shell
sh -c 'sh -c "$(curl -sL https://api.controld.com/dl)"'
```

Windows user and prefer Powershell (who doesn't)? No problem, execute this command instead in administrative cmd:
```shell
powershell -Command "(Invoke-WebRequest -Uri 'https://api.controld.com/dl' -UseBasicParsing).Content | Set-Content 'ctrld_install.bat'" && ctrld_install.bat
```

Or you can pull and run a Docker container from [Docker Hub](https://hub.docker.com/r/controldns/ctrld)
```
$ docker pull controldns/ctrld
```

## Download Manually
Alternatively, if you know what you're doing you can download pre-compiled binaries from the [Releases](https://github.com/Control-D-Inc/ctrld/releases) section for the appropriate platform. 

## Build
Lastly, you can build `ctrld` from source which requires `go1.21+`:

```shell
$ go build ./cmd/ctrld
```

or

```shell
$ go install github.com/Control-D-Inc/ctrld/cmd/ctrld@latest
```

or 

```
$ docker build -t controldns/ctrld . -f docker/Dockerfile
$ docker run -d --name=ctrld -p 53:53/tcp -p 53:53/udp controldns/ctrld --cd=RESOLVER_ID_GOES_HERE -vv
```


# Usage
The cli is self documenting, so free free to run `--help` on any sub-command to get specific usages. 

## Arguments
```
        __         .__       .___
  _____/  |________|  |    __| _/
_/ ___\   __\_  __ \  |   / __ |
\  \___|  |  |  | \/  |__/ /_/ |
 \___  >__|  |__|  |____/\____ |
     \/ dns forwarding proxy  \/

Usage:
  ctrld [command]

Available Commands:
  run         Run the DNS proxy server
  service     Manage ctrld service
  start       Quick start service and configure DNS on interface
  stop        Quick stop service and remove DNS from interface
  restart     Restart the ctrld service
  reload      Reload the ctrld service
  status      Show status of the ctrld service
  uninstall   Stop and uninstall the ctrld service
  clients     Manage clients
  upgrade     Upgrading ctrld to latest version

Flags:
  -h, --help            help for ctrld
  -s, --silent          do not write any log output
  -v, --verbose count   verbose log output, "-v" basic logging, "-vv" debug level logging
      --version         version for ctrld

Use "ctrld [command] --help" for more information about a command.
```

## Basic Run Mode
To start the server with default configuration, simply run: `./ctrld run`. This will create a generic `ctrld.toml` file in the **working directory** and start the application in foreground. 
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

If `verify.controld.com` resolves, you're successfully using the default Control D upstream. From here, you can start editing the config file and go nuts with it. To enforce a new config, restart the server. 

## Service Mode
To run the application in service mode on any Windows, MacOS, Linux distibution or supported router, simply run: `./ctrld start` as system/root user. This will create a generic `ctrld.toml` file in the **user home** directory (on Windows) or `/etc/controld/` (almost everywhere else), start the system service, and configure the listener on the default network interface. Service will start on OS boot.

When Control D upstreams are used, `ctrld` willl [relay your network topology](https://docs.controld.com/docs/device-clients) to Control D (LAN IPs, MAC addresses, and hostnames), and you will be able to see your LAN devices in the web panel, view analytics and apply unique profiles to them. 

In order to stop the service, and restore your DNS to original state, simply run `./ctrld stop`. If you wish to stop and uninstall the service permanently, run `./ctrld uninstall`. 


### Supported Routers
You can run `ctrld` on any supported router, which will function similarly to the Service Mode mentioned above. The list of supported routers and firmware includes:
- Asus Merlin
- DD-WRT
- Firewalla
- FreshTomato
- GL.iNet
- OpenWRT
- pfSense / OPNsense
- Synology 
- Ubiquiti (UniFi, EdgeOS)

`ctrld` will attempt to interface with dnsmasq whenever possible and set itself as the upstream, while running on port 5354. On FreeBSD based OSes, `ctrld` will terminate dnsmasq and unbound in order to be able to listen on port 53 directly.  


### Control D Auto Configuration
Application can be started with a specific resolver config, instead of the default one. Simply supply your Resolver ID with a `--cd` flag, when using the `run` (foreground) or `start` (service) modes. 

The following command will start the application in foreground mode, using the free "p2" resolver, which blocks Ads & Trackers. 

```shell
./ctrld run --cd p2
```

Alternatively, you can use your own personal Control D Device resolver, and start the application in service mode. Your resolver ID is displayed on the "Show Resolvers" screen for the relevant Control D Device. 

```shell
./ctrld start --cd abcd1234
```

Once you run the above commands (in service mode only), the following things will happen:
- You resolver configuration will be fetched from the API, and config file templated with the resolver data
- Application will start as a service, and keep running (even after reboot) until you run the `stop` or `uninstall` sub-commands
- Your default network interface will be updated to use the listener started by the service
- All OS DNS queries will be sent to the listener

# Configuration
See [Configuration Docs](docs/config.md).

## Example 
- Start `listener.0` on 127.0.0.1:53
- Accept queries from any source address
- Send all queries to `upstream.0` via DoH protocol

### Default Config
```toml
[listener]

  [listener.0]
    ip = ""
    port = 0
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

`ctrld` will pick a working config for `listener.0` then writing the default config to disk for the first run.

## Advanced Configuration
The above is the most basic example, which will work out of the box. If you're looking to do advanced configurations using policies, see [Configuration Docs](docs/config.md) for complete documentation of the config file.

You can also supply configuration via launch argeuments, in [Ephemeral Mode](docs/ephemeral_mode.md).

## Contributing
See [Contribution Guideline](./docs/contributing.md)

## Roadmap
The following functionality is on the roadmap and will be available in future releases. 
- DNS intercept mode
- Direct listener mode
- Support for more routers (let us know which ones)
