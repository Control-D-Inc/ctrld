# ctrld

![Test](https://github.com/Control-D-Inc/ctrld/actions/workflows/ci.yml/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/Control-D-Inc/ctrld.svg)](https://pkg.go.dev/github.com/Control-D-Inc/ctrld)
[![Go Report Card](https://goreportcard.com/badge/github.com/Control-D-Inc/ctrld)](https://goreportcard.com/report/github.com/Control-D-Inc/ctrld)

A highly configurable DNS forwarding proxy with support for:
- Multiple listeners for incoming queries
- Multiple upstreams with fallbacks
- Multiple network policy driven DNS query steering
- Policy driven domain based "split horizon" DNS with wildcard support

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


## OS Support
- Windows (386, amd64, arm)
- Mac (amd64, arm64)
- Linux (386, amd64, arm, mips)
- Common routers (See Router Mode below)

# Install
There are several ways to download and install `ctrld.

## Quick Install
The simplest way to download and install `ctrld` is to use the following installer command on any UNIX-like platform:

```shell
sh -c 'sh -c "$(curl -sL https://api.controld.com/dl)"'
```

Windows user and prefer Powershell (who doesn't)? No problem, execute this command instead in administrative cmd:
```shell
powershell -Command "(Invoke-WebRequest -Uri 'https://api.controld.com/dl' -UseBasicParsing).Content | Set-Content 'ctrld_install.bat'" && ctrld_install.bat
```

## Download Manually
Alternatively, if you know what you're doing you can download pre-compiled binaries from the [Releases](https://github.com/Control-D-Inc/ctrld/releases) section for the appropriate platform. 

## Build
Lastly, you can build `ctrld` from source which requires `go1.19+`:

```shell
$ go build ./cmd/ctrld
```

or

```shell
$ go install github.com/Control-D-Inc/ctrld/cmd/ctrld@latest
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
  setup       Auto-setup Control D on a router.

Supported platforms:

    ₒ ddwrt
    ₒ merlin
    ₒ openwrt
    ₒ ubios
    ₒ auto - detect the platform you are running on


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
To run the application in service mode on any Windows, MacOS or Linux distibution, simply run: `./ctrld start` as system/root user. This will create a generic `ctrld.toml` file in the **user home** directory (on Windows) or `/etc/controld/` (everywhere else), start the system service, and configure the listener on the default network interface. Service will start on OS boot.

In order to stop the service, and restore your DNS to original state, simply run `./ctrld stop`. If you wish to uninstall the service permanently, run `./ctrld service uninstall`. 

For granular control of the service, run the `service` command. Each sub-command has its own help section so you can see what arguments you can supply.

```
  Manage ctrld service

  Usage:
    ctrld service [command]

  Available Commands:
    interfaces  Manage network interfaces
    restart     Restart the ctrld service
    start       Start the ctrld service
    status      Show status of the ctrld service
    stop        Stop the ctrld service
    uninstall   Uninstall the ctrld service

  Flags:
    -h, --help   help for service

  Global Flags:
    -v, --verbose count   verbose log output, "-v" basic logging, "-vv" debug level logging

  Use "ctrld service [command] --help" for more information about a command.
```

## Router Mode
You can run `ctrld` on any supported router, which will function similarly to the Service Mode mentioned above. The list of supported routers and firmware includes:
- Asus Merlin
- DD-WRT
- FreshTomato
- GL.iNet
- OpenWRT
- pfSense
- Synology 
- Ubiquiti (UniFi, EdgeOS)

In order to start `ctrld` as a DNS provider, simply run `./ctrld setup auto` command. 

In this mode, and when Control D upstreams are used, the router will [relay your network topology](https://docs.controld.com/docs/device-clients) to Control D (LAN IPs, MAC addresses, and hostnames), and you will be able to see your LAN devices in the web panel, view analytics and apply unique profiles to them. 

### Control D Auto Configuration
Application can be started with a specific resolver config, instead of the default one. Simply supply your Resolver ID with a `--cd` flag, when using the `run` (foreground) or `start` (service) or `setup` (router) modes. 

The following command will start the application in foreground mode, using the free "p2" resolver, which blocks Ads & Trackers. 

```shell
./ctrld run --cd p2
```

Alternatively, you can use your own personal Control D Device resolver, and start the application in service mode. Your resolver ID is displayed on the "Show Resolvers" screen for the relevant Control D Device. 

```shell
./ctrld start --cd abcd1234
```

You can do the same while starting in router mode:
```shell
./ctrld setup auto --cd abcd1234
```

Once you run the above commands (in service or router modes only), the following things will happen:
- You resolver configuration will be fetched from the API, and config file templated with the resolver data
- Application will start as a service, and keep running (even after reboot) until you run the `stop` or `service uninstall` sub-commands
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

## Advanced Configuration
The above is the most basic example, which will work out of the box. If you're looking to do advanced configurations using policies, see [Configuration Docs](docs/config.md) for complete documentation of the config file.

You can also supply configuration via launch argeuments, in [Ephemeral Mode](docs/ephemeral_mode.md).

## Contributing
See [Contribution Guideline](./docs/contributing.md)

## Roadmap
The following functionality is on the roadmap and will be available in future releases. 
- Prometheus metrics exporter 
- DNS intercept mode
- Support for more routers (let us know which ones)
