# ctrld

![Test](https://github.com/Control-D-Inc/ctrld/actions/workflows/ci.yml/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/Control-D-Inc/ctrld.svg)](https://pkg.go.dev/github.com/Control-D-Inc/ctrld)
[![Go Report Card](https://goreportcard.com/badge/github.com/Control-D-Inc/ctrld)](https://goreportcard.com/report/github.com/Control-D-Inc/ctrld)

![ctrld splash image](/docs/ctrldsplash.png)

A highly configurable DNS forwarding proxy with support for:
- Multiple listeners for incoming queries
- Multiple upstreams with fallbacks
- Multiple network policy driven DNS query steering (via network cidr, MAC address or FQDN)
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
- Windows Server (386, amd64)
- MacOS (amd64, arm64)
- Linux (386, amd64, arm, mips)
- FreeBSD (386, amd64, arm)
- Common routers (See below)


### Supported Routers
You can run `ctrld` on any supported router. The list of supported routers and firmware includes:
- Asus Merlin
- DD-WRT
- Firewalla
- FreshTomato
- GL.iNet
- OpenWRT
- pfSense / OPNsense
- Synology 
- Ubiquiti (UniFi, EdgeOS)

`ctrld` will attempt to interface with dnsmasq (or Windows Server) whenever possible and set itself as the upstream, while running on port 5354. On FreeBSD based OSes, `ctrld` will terminate dnsmasq and unbound in order to be able to listen on port 53 directly.  

# Install
There are several ways to download and install `ctrld`.

## Quick Install
The simplest way to download and install `ctrld` is to use the following installer command on any UNIX-like platform:

```shell
sh -c 'sh -c "$(curl -sL https://api.controld.com/dl)"'
```

Windows user and prefer Powershell (who doesn't)? No problem, execute this command instead in administrative PowerShell:
```shell
(Invoke-WebRequest -Uri 'https://api.controld.com/dl/ps1' -UseBasicParsing).Content | Set-Content "$env:TEMPctrld_install.ps1"; Invoke-Expression "& '$env:TEMPctrld_install.ps1'"
```

Or you can pull and run a Docker container from [Docker Hub](https://hub.docker.com/r/controldns/ctrld)
```shell
docker run -d --name=ctrld -p 127.0.0.1:53:53/tcp -p 127.0.0.1:53:53/udp controldns/ctrld:latest
```

## Download Manually
Alternatively, if you know what you're doing you can download pre-compiled binaries from the [Releases](https://github.com/Control-D-Inc/ctrld/releases) section for the appropriate platform. 

## Build
Lastly, you can build `ctrld` from source which requires `go1.21+`:

```shell
go build ./cmd/ctrld
```

or

```shell
go install github.com/Control-D-Inc/ctrld/cmd/ctrld@latest
```

or 

```shell
docker build -t controldns/ctrld . -f docker/Dockerfile
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
  start       Quick start service and configure DNS on interface
  stop        Quick stop service and remove DNS from interface
  restart     Restart the ctrld service
  reload      Reload the ctrld service
  status      Show status of the ctrld service
  uninstall   Stop and uninstall the ctrld service
  service     Manage ctrld service
  clients     Manage clients
  upgrade     Upgrading ctrld to latest version
  log         Manage runtime debug logs

Flags:
  -h, --help            help for ctrld
  -s, --silent          do not write any log output
  -v, --verbose count   verbose log output, "-v" basic logging, "-vv" debug level logging
      --version         version for ctrld

Use "ctrld [command] --help" for more information about a command.
```

## Basic Run Mode
This is the most basic way to run `ctrld`, in foreground mode. Unless you already have a config file, a default one will be generated. 

### Command

Windows (Admin Shell)
  ```shell
  ctrld.exe run
  ```

Linux or Macos
  ```shell
  sudo ctrld run
  ```

You can then run a test query using a DNS client, for example, `dig`:
  ```
  $ dig verify.controld.com @127.0.0.1 +short
  api.controld.com.
  147.185.34.1
  ```

If `verify.controld.com` resolves, you're successfully using the default Control D upstream. From here, you can start editing the config file that was generated. To enforce a new config, restart the server. 

## Service Mode
This mode will run the application as a background system service on any Windows, MacOS, Linux, FreeBSD distribution or supported router. This will create a generic `ctrld.toml` file in the **C:\ControlD** directory (on Windows) or `/etc/controld/` (almost everywhere else), start the system service, and **configure the listener on all physical network interface**. Service will start on OS boot.

When Control D upstreams are used on a router type device, `ctrld` will [relay your network topology](https://docs.controld.com/docs/device-clients) to Control D (LAN IPs, MAC addresses, and hostnames), and you will be able to see your LAN devices in the web panel, view analytics and apply unique profiles to them. 

### Command

Windows (Admin Shell)
  ```shell
  ctrld.exe start
  ```

Linux or Macos
  ```
  sudo ctrld start
  ```

If `ctrld` is not in your system path (you installed it manually), you will need to run the above commands from the directory where you installed `ctrld`. 

In order to stop the service, and restore your DNS to original state, simply run `ctrld stop`. If you wish to stop and uninstall the service permanently, run `ctrld uninstall`. 

## Unmanaged Service Mode
This mode functions similarly to the "Service Mode" above except it will simply start a system service and the config defined listeners, but **will not make any changes to any network interfaces**. You can then set the `ctrld` listener(s) IP on the desired network interfaces manually. 

### Command

Windows (Admin Shell)
  ```shell
  ctrld.exe service start
  ```

Linux or Macos
  ```shell
  sudo ctrld service start
  ```

# Configuration
`ctrld` can be configured in variety of different ways, which include: API, local config file or via cli launch args. 

## API Based Auto Configuration
Application can be started with a specific Control D resolver config, instead of the default one. Simply supply your Resolver ID with a `--cd` flag, when using the `start` (service) mode. In this mode, the application will automatically choose a non-conflicting IP and/or port and configure itself as the upstream to whatever process is running on port 53 (like dnsmasq or Windows DNS Server). This mode is used when the 1 liner installer command from the Control D onboarding guide is executed. 

The following command will use your own personal Control D Device resolver, and start the application in service mode. Your resolver ID is displayed on the "Show Resolvers" screen for the relevant Control D Endpoint. 

Windows (Admin Shell)
```shell
ctrld.exe start --cd abcd1234
```

Linux or Macos
```shell
sudo ctrld start --cd abcd1234
```

Once you run the above command, the following things will happen:
- You resolver configuration will be fetched from the API, and config file templated with the resolver data
- Application will start as a service, and keep running (even after reboot) until you run the `stop` or `uninstall` sub-commands
- All physical network interface will be updated to use the listener started by the service or dnsmasq upstream will be switched to `ctrld`
- All DNS queries will be sent to the listener

## Manual Configuration 
`ctrld` is entirely config driven and can be configured in many different ways, please see [Configuration Docs](docs/config.md).

### Example
```toml
[listener]

  [listener.0]
    ip = '0.0.0.0'
    port = 53

[network]

  [network.0]
    cidrs = ["0.0.0.0/0"]
    name = "Network 0"

[upstream]

  [upstream.0]
    bootstrap_ip = "76.76.2.11"
    endpoint = "https://freedns.controld.com/p1"
    name = "Control D - Anti-Malware"
    timeout = 5000
    type = "doh"
```

The above basic config will:
- Start listener on 0.0.0.0:53
- Accept queries from any source address
- Send all queries to `https://freedns.controld.com/p1` using DoH protocol

## CLI Args
If you're unable to use a config file, `ctrld` can be be supplied with basic configuration via launch arguments, in [Ephemeral Mode](docs/ephemeral_mode.md).

### Example
```
ctrld run --listen=127.0.0.1:53 --primary_upstream=https://freedns.controld.com/p2 --secondary_upstream=10.0.10.1:53 --domains=*.company.int,very-secure.local --log /path/to/log.log
```

The above will start a foreground process and:
- Listen on `127.0.0.1:53` for DNS queries
- Forward all queries to `https://freedns.controld.com/p2` using DoH protocol, while...
- Excluding `*.company.int` and `very-secure.local` matching queries, that are forwarded to `10.0.10.1:53`
- Write a debug log to `/path/to/log.log`

## Contributing
See [Contribution Guideline](./docs/contributing.md)
