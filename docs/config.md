# Configuration File
The config file allows for advanced configuration of the `ctrld` utility to cover a vast array of use cases. 
1. Source IP based DNS routing policies
2. Destination IP based DNS routing policies 
3. Split horizon DNS

- [Config Location](#config-location)
- [Example Config](#example-config)
  - [Service](#service) - general configurations 
  - [Upstreams](#upstream) - where to send DNS queries
  - [Networks](#network) - where did the DNS queries come from
  - [Listeners](#listener) - what receives DNS queries and defines policies
      - [Policies](#policy) - what receives DNS queries and defines policies


## Config Location
`ctrld` uses [TOML][toml_link] format for its configuration file. Default configuration file is `ctrld.toml` found in following order:

 - `/etc/controld` on *nix.
 - User's home directory on Windows.
 - Same directory with `ctrld` binary on these routers:
   - `ddwrt`
   - `merlin`
   - `freshtomato`
 - Current directory.

The user can choose to override default value using command line `--config` or `-c`:

```shell
ctrld run --config /path/to/myconfig.toml
```

If no configuration files found, a default `ctrld.toml` file will be created in the current directory.

In pre v1.1.0, `config.toml` file was used, so for compatibility, `ctrld` will still read `config.toml`
if it's existed.

# Example Config

```toml
[service]
    log_level = "info"
    log_path = ""
    cache_enable = true
    cache_size = 4096
    cache_ttl_override = 60
    cache_serve_stale = true

[network.0]
    cidrs = ["0.0.0.0/0"]
    name = "Everyone"

[network.1]
    cidrs = ["10.10.10.0/24"]
    name = "Admins"

[upstream.0]
    bootstrap_ip = "76.76.2.11"
    endpoint = "https://freedns.controld.com/p1"
    name = "Control D - Anti-Malware"
    timeout = 5000
    type = "doh"
    ip_stack = "both"

[upstream.1]
    bootstrap_ip = "76.76.2.11"
    endpoint = "p2.freedns.controld.com"
    name = "Control D - No Ads"
    timeout = 5000
    type = "doq"
    ip_stack = "split"

[upstream.2]
    bootstrap_ip = "76.76.2.22"
    endpoint = "private.dns.controld.com"
    name = "Control D - Private"
    timeout = 5000
    type = "dot"
    ip_stack = "v4"

[listener.0]
    ip = "127.0.0.1"
    port = 53

[listener.0.policy]
    name = "My Policy"
    networks = [
        {"network.0" = ["upstream.1"]},
    ]
    rules = [
        {"*.local" = ["upstream.1"]},
        {"test.com" = ["upstream.2", "upstream.1"]},
    ]

[listener.1]
    ip = "127.0.0.69"
    port = 53
    restricted = true
```

See below for details on each configuration block.

## Service
The `[service]` section controls general behaviors. 

```toml
[service]
    log_level = "debug"
    log_path = "log.txt"
```

### log_level
Logging level you wish to enable.

 - Type: string
 - Required: no
 - Valid values: `debug`, `info`, `warn`, `notice`, `error`, `fatal`, `panic`
 - Default: `notice`


### log_path
Relative or absolute path of the log file. 

- Type: string
- Required: no
- Default: ""

### cache_enable
When `cache_enable = true`, all resolved DNS query responses will be cached for duration of the upstream record TTLs.

- Type: boolean
- Required: no
- Default: false

### cache_size
The number of cached records, must be a positive integer. Tweaking this value with care depends on your available RAM. 
A minimum value `4096` should be enough for most use cases.

An invalid `cache_size` value will disable the cache, regardless of `cache_enable` value.

- Type: int
- Required: no
- Default: 4096

### cache_ttl_override
When `cache_ttl_override` is set to a positive value (in seconds), TTLs are overridden to this value and cached for this long.

- Type: int
- Required: no
- Default: 0

### cache_serve_stale
When `cache_serve_stale = true`, in cases of upstream failures (upstreams not reachable), `ctrld` will keep serving
stale cached records (regardless of their TTLs) until upstream comes online.

- Type: boolean
- Required: no
- Default: false

### cache_flush_domains
When `ctrld` receives query with domain name in `cache_flush_domains`, the local cache will be discarded
before serving the query.

- Type: array of strings
- Required: no

### max_concurrent_requests
The number of concurrent requests that will be handled, must be a non-negative integer. 
Tweaking this value depends on the capacity of your system.

- Type: number
- Required: no
- Default: 256

### discover_mdns
Perform LAN client discovery using mDNS. This will spawn a listener on port 5353. 

- Type: boolean
- Required: no
- Default: true

### discover_arp
Perform LAN client discovery using ARP.  

- Type: boolean
- Required: no
- Default: true

### discover_dhcp
Perform LAN client discovery using DHCP leases files. Common file locations are auto-discovered.  

- Type: boolean
- Required: no
- Default: true

### discover_ptr
Perform LAN client discovery using PTR queries.  

- Type: boolean
- Required: no
- Default: true

### discover_hosts
Perform LAN client discovery using hosts file.

- Type: boolean
- Required: no
- Default: true

### discover_refresh_interval
Time in seconds between each discovery refresh loop to update new client information data. 
The default value is 120 seconds, lower this value to make the discovery process run more aggressively.

- Type: integer
- Required: no
- Default: 120

### dhcp_lease_file_path
Relative or absolute path to a custom DHCP leases file location. 

- Type: string
- Required: no
- Default: ""

### dhcp_lease_file_format
DHCP leases file format. 

- Type: string
- Required: no
- Valid values: `dnsmasq`, `isc-dhcp`, `kea-dhcp4`
- Default: ""

### client_id_preference
Decide how the client ID is generated. By default client ID will use both MAC address and Hostname i.e. `hash(mac + host)`. To override this behavior, select one of the 2 allowed values to scope client ID to just MAC address OR Hostname.  

- Type: string
- Required: no
- Valid values: `mac`, `host`
- Default: ""

### metrics_query_stats
If set to `true`, collect and export the query counters, and show them in `clients list` command.

- Type: boolean
- Required: no
- Default: false

### metrics_listener
Specifying the `ip` and `port` of the Prometheus metrics server. The Prometheus metrics will be available on: `http://ip:port/metrics`. You can also append `/metrics/json` to get the same data in json format. 

- Type: string
- Required: no
- Default: ""

### dns_watchdog_enabled
Checking DNS changes to network interfaces and reverting to ctrld's own settings.

The DNS watchdog process only runs on Windows and MacOS.

- Type: boolean
- Required: no
- Default: true

### dns_watchdog_interval
Time duration between each DNS watchdog iteration.

A duration string is a possibly signed sequence of decimal numbers, each with optional fraction and a unit suffix,
such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".

If the time duration is non-positive, default value will be used.

- Type: time duration string
- Required: no
- Default: 20s

### refresh_time
Time in seconds between each iteration that reloads custom config if changed.

The value must be a positive number, any invalid value will be ignored and default value will be used.
- Type: number
- Required: no
- Default: 3600

## Upstream
The `[upstream]` section specifies the DNS upstream servers that `ctrld` will forward DNS requests to.

```toml
[upstream.0]
  bootstrap_ip = ""
  endpoint = "https://freedns.controld.com/p1"
  name = "Control D - DOH"
  timeout = 5000
  type = "doh"
  ip_stack = "split"
  
[upstream.1]
  bootstrap_ip = ""
  endpoint = "https://freedns.controld.com/p1"
  name = "Control D - DOH3"
  timeout = 5000
  type = "doh3"
  ip_stack = "both"
  
[upstream.2]
  bootstrap_ip = ""
  endpoint = "p1.freedns.controld.com"
  name = "Controld D - DOT"
  timeout = 5000
  type = "dot"
  ip_stack = "v4"
  
[upstream.3]
  bootstrap_ip = ""
  endpoint = "p1.freedns.controld.com"
  name = "Controld D - DOT"
  timeout = 5000
  type = "doq"
  ip_stack = "v6"
  
[upstream.4]
  bootstrap_ip = ""
  endpoint = "76.76.2.2"
  name = "Control D - Ad Blocking"
  timeout = 5000
  type = "legacy"
  ip_stack = "both"
```

### bootstrap_ip
IP address of upstream DNS server when hostname or URL is used. This exists to prevent the bootstrapping cycle problem.
For example, if the `Endpoint` is set to `https://freedns.controld.com/p1`, `ctrld` needs to know the ip address of `freedns.controld.com` to be able to do communication. To do that, `ctrld` may need to use OS resolver, which may or may not be set.

If `bootstrap_ip` is empty, `ctrld` will resolve this itself using its own bootstrap DNS, normal users should not care about `bootstrap_ip` and just leave it empty.

 - type: ip address string
 - required: no
 - Default: ""

### endpoint
IP address, hostname or URL of upstream DNS. Used together with `Type` of the endpoint.

 - Type: string
 - Required: yes

 Default ports are implied for each protocol, but can be overriden. ie. `p1.freedns.controld.com:1024`

### name
Human-readable name of the upstream.

- Type: string
- Required: no
- Default: ""

### timeout
Timeout in milliseconds before request failsover to the next upstream (if defined). 

Value `0` means no timeout.

 - Type: number
 - Required: no
 - Default: 0

### type
The protocol that `ctrld` will use to send DNS requests to upstream.

 - Type: string
 - Required: yes
 - Valid values: `doh`, `doh3`, `dot`, `doq`, `legacy`

### ip_stack
Specifying what kind of ip stack that `ctrld` will use to connect to upstream.

 - Type: string
 - Required: no
 - Valid values:
   - `both`: using either ipv4 or ipv6.
   - `v4`:   only dial upstream via IPv4, never dial IPv6.
   - `v6`:   only dial upstream via IPv6, never dial IPv4.
   - `split`:
     - If `A` record is requested -> dial via ipv4.
     - If `AAAA` or any other record is requested -> dial ipv6 (if available, otherwise ipv4)

If `ip_stack` is empty, or undefined:

 - Default value is `both` for non-Control D resolvers.
 - Default value is `split` for Control D resolvers.

### send_client_info
Specifying whether to include client info when sending query to upstream. **This will only work with `doh` or `doh3` type upstreams.** 

- Type: boolean
- Required: no
- Default:
  - `true` for ControlD upstreams.
  - `false` for other upstreams.

### discoverable
Specifying whether the upstream can be used for PTR discovery.

- Type: boolean
- Required: no
- Default:
    - `true` for loopback/RFC1918/CGNAT IP address.
    - `false` for public IP address.

## Network
The `[network]` section defines networks from which DNS queries can originate from. These are used in policies. You can define multiple networks, and each one can have multiple cidrs.

```toml
[network.0]
  cidrs = ["0.0.0.0/0"]
  name = "Any Network"
  
[network.1]
  cidrs = ["192.168.1.0/24"]
  name = "Home Wifi "
```

### name
Name of the network.

 - Type: string
 - Required: no
 - Default: ""

### cidrs
Specifies the network addresses that the `listener` will accept requests from. You will see more details in the listener policy section.

 - Type: array of network CIDR string
 - Required: no
 - Default: []


## listener
The `[listener]` section specifies the ip and port of the local DNS server. You can have multiple listeners, and attached policies.

```toml
[listener.0]
  ip = "127.0.0.1"
  port = 53
  
[listener.1]
  ip = "10.10.10.1"
  port = 53
  restricted = true
```

### ip
IP address that serves the incoming requests. If `ip` is empty, ctrld will listen on all available addresses.

- Type: ip address string
- Required: no
- Default: "0.0.0.0" or RFC1918 addess or "127.0.0.1" (depending on platform)

### port
Port number that the listener will listen on for incoming requests. If `port` is `0`, a random available port will be chosen.

- Type: number
- Required: no
- Default: 0 or 53 or 5354 (depending on platform)

### restricted
If set to `true`, makes the listener `REFUSED` DNS queries from all source IP addresses that are not explicitly defined in the policy using a `network`. 

- Type: bool
- Required: no
- Default: false

### allow_wan_clients
The listener will refuse DNS queries from WAN IPs using `REFUSED` RCODE by default. Set to `true` to disable this behavior, but this is not recommended. 

- Type: bool
- Required: no
- Default: false

### policy
Allows `ctrld` to set policy rules to determine which upstreams the requests will be forwarded to.
If no `policy` is defined or the requests do not match any policy rules, it will be forwarded to corresponding upstream of the listener. For example, the request to `listener.0` will be forwarded to `upstream.0`.

The policy `rule` syntax is a simple `toml` inline table with exactly one key/value pair per rule. `key` is either:

 - Network.
 - Domain.
 - Mac Address.

Value is the list of the upstreams.

For example:

```toml
[listener.0.policy]
name = "My Policy"

networks = [
    {"network.0" = ["upstream.1"]},
]

rules = [
    {"*.local" = ["upstream.1"]},
    {"test.com" = ["upstream.2", "upstream.1"]},
]

macs = [
    {"14:54:4a:8e:08:2d" = ["upstream.3"]},
]
```

Above policy will:

- Forward requests on `listener.0` for `.local` suffixed domains to `upstream.1`.
- Forward requests on `listener.0` for `test.com` to `upstream.2`. If timeout is reached, retry on `upstream.1`.
- Forward requests on `listener.0` from client with Mac `14:54:4a:8e:08:2d` to `upstream.3`.
- Forward requests on `listener.0` from `network.0` to `upstream.1`.
- All other requests on `listener.0` that do not match above conditions will be forwarded to `upstream.0`.

An empty upstream would not route the request to any defined upstreams, and use the OS default resolver.

```toml
[listener.0.policy]
name = "OS Resolver"

rules = [
    {"*.local" = []},
]
```

---

Note that the order of matching preference:

```
rules => macs => networks
```

And within each policy, the rules are processed from top to bottom.

---

#### name
`name` is the name for the policy.

- Type: string
- Required: no
- Default: ""

### networks:
`networks` is the list of network rules of the policy.

- Type: array of networks
- Required: no
- Default: []

### rules:
`rules` is the list of domain rules within the policy. Domain can be either FQDN or wildcard domain.

- Type: array of rule
- Required: no
- Default: []

### macs:
`macs` is the list of mac rules within the policy. Mac address value is case-insensitive.

- Type: array of macs
- Required: no
- Default: []

### failover_rcodes
For non success response, `failover_rcodes` allows the request to be forwarded to next upstream, if the response `RCODE` matches any value defined in `failover_rcodes`.

- Type: array of strings
- Required: no
- Default: []
- 
For example:

```toml
[listener.0.policy]
name = "My Policy"
failover_rcodes = ["NXDOMAIN", "SERVFAIL"]
networks = [
	{"network.0" = ["upstream.0", "upstream.1"]},
]
```

If `upstream.0` returns a NXDOMAIN response, the request will be forwarded to `upstream.1` instead of returning immediately to the client.

See all available DNS Rcodes value [here][rcode_link].

[toml_link]: https://toml.io/en
[rcode_link]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
