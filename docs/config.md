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
`ctrld` uses [TOML](toml_link) format for its configuration file. Default configuration file is `config.toml` found in following order:

 - `$HOME/.ctrld`
 - Current directory

The user can choose to override default value using command line `--config` or `-c`:

```shell
ctrld run --config /path/to/myconfig.toml
```

If no configuration files found, a default `config.toml` file will be created in the current directory.

# Example Config

```toml
[service]
    log_level = "info"
    log_path = ""

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

[upstream.1]
    bootstrap_ip = "76.76.2.11"
    endpoint = "p2.freedns.controld.com"
    name = "Control D - No Ads"
    timeout = 5000
    type = "doq"

[upstream.2]
    bootstrap_ip = "76.76.2.22"
    endpoint = "private.dns.controld.com"
    name = "Control D - Private"
    timeout = 5000
    type = "dot"

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
 - Valid values: `debug`, `info`, `warn`, `error`, `fatal`, `panic`
 - Default: `info`


### log_path
Relative or absolute path of the log file. 

- Type: string
- Required: no

The above config will look like this at query time.

```
2022-11-14T22:18:53.808 INF Setting bootstrap IP for upstream.0 bootstrap_ip=76.76.2.11
2022-11-14T22:18:53.808 INF Starting DNS server on listener.0: 127.0.0.1:53
2022-11-14T22:18:56.381 DBG [9fd5d3] 127.0.0.1:53978 -> listener.0: 127.0.0.1:53: received query: verify.controld.com
2022-11-14T22:18:56.381 INF [9fd5d3] no policy, no network, no rule -> [upstream.0]
2022-11-14T22:18:56.381 DBG [9fd5d3] sending query to upstream.0: Control D - DOH Free
2022-11-14T22:18:56.381 DBG [9fd5d3] debug dial context freedns.controld.com:443 - tcp - 76.76.2.0
2022-11-14T22:18:56.381 DBG [9fd5d3] sending doh request to: 76.76.2.11:443
2022-11-14T22:18:56.420 DBG [9fd5d3] received response of 118 bytes in 39.662597ms
```

## Upstream
The `[upstream]` section specifies the DNS upstream servers that `ctrld` will forward DNS requests to.

```toml
[upstream.0]
  bootstrap_ip = ""
  endpoint = "https://freedns.controld.com/p1"
  name = "Control D - DOH"
  timeout = 5000
  type = "doh"
  
[upstream.1]
  bootstrap_ip = ""
  endpoint = "https://freedns.controld.com/p1"
  name = "Control D - DOH3"
  timeout = 5000
  type = "doh3"
  
[upstream.2]
  bootstrap_ip = ""
  endpoint = "p1.freedns.controld.com"
  name = "Controld D - DOT"
  timeout = 5000
  type = "dot"
  
[upstream.3]
  bootstrap_ip = ""
  endpoint = "p1.freedns.controld.com"
  name = "Controld D - DOT"
  timeout = 5000
  type = "doq"
  
[upstream.4]
  bootstrap_ip = ""
  endpoint = "76.76.2.2"
  name = "Control D - Ad Blocking"
  timeout = 5000
  type = "legacy"
```

### bootstrap_ip
IP address of upstream DNS server when hostname or URL is used. This exists to prevent the bootstrapping cycle problem.
For example, if the `Endpoint` is set to `https://freedns.controld.com/p1`, `ctrld` needs to know the ip address of `freedns.controld.com` to be able to do communication. To do that, `ctrld` may need to use OS resolver, which may or may not be set.

If `bootstrap_ip` is empty, `ctrld` will resolve this itself using its own bootstrap DNS, normal users should not care about `bootstrap_ip` and just leave it empty.

 - type: ip address string
 - required: no

### endpoint
IP address, hostname or URL of upstream DNS. Used together with `Type` of the endpoint.

 - Type: string
 - Required: yes

 Default ports are implied for each protocol, but can be overriden. ie. `p1.freedns.controld.com:1024`

### name
Human-readable name of the upstream.

- Type: string
- Required: no

### timeout
Timeout in milliseconds before request failsover to the next upstream (if defined). 

Value `0` means no timeout.

 - Type: number
 - required: no

### type
The protocol that `ctrld` will use to send DNS requests to upstream.

 - Type: string
 - required: yes
 - Valid values: `doh`, `doh3`, `dot`, `doq`, `legacy`, `os`

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

### cidrs
Specifies the network addresses that the `listener` will accept requests from. You will see more details in the listener policy section.

 - Type: array of network CIDR string
 - Required: no


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
IP address that serves the incoming requests.

- Type: string
- Required: yes

### port
Port number that the listener will listen on for incoming requests.

- Type: number
- Required: yes

### restricted
If set to `true` makes the listener `REFUSE` DNS queries from all source IP addresses that are not explicitly defined in the policy using a `network`. 

- Type: bool
- Required: no

### policy
Allows `ctrld` to set policy rules to determine which upstreams the requests will be forwarded to.
If no `policy` is defined or the requests do not match any policy rules, it will be forwarded to corresponding upstream of the listener. For example, the request to `listener.0` will be forwarded to `upstream.0`.

The policy `rule` syntax is a simple `toml` inline table with exactly one key/value pair per rule. `key` is either the `network` or a domain. Value is the list of the upstreams. For example:

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
```

Above policy will:
- Forward requests on `listener.0` from `network.0` to `upstream.1`.
- Forward requests on `listener.0` for `.local` suffixed domains to `upstream.1`.
- Forward requests on `listener.0` for `test.com` to `upstream.2`. If timeout is reached, retry on `upstream.1`.
- All other requests on `listener.0` that do not match above conditions will be forwarded to `upstream.0`.

#### name
`name` is the name for the policy.

- Type: string
- Required: no

### networks:
`networks` is the list of network rules of the policy.

- type: array of networks

### rules:
`rules` is the list of domain rules within the policy. Domain can be either FQDN or wildcard domain.

- type: array of rule

### failover_rcodes
For non success response, `failover_rcodes` allows the request to be forwarded to next upstream, if the response `RCODE` matches any value defined in `failover_rcodes`. For example:

```toml
[listener.0.policy]
name = "My Policy"
failover_rcodes = ["NXDOMAIN", "SERVFAIL"]
networks = [
	{"network.0" = ["upstream.0", "upstream.1"]},
]
```

If `upstream.0` returns a NXDOMAIN response, the request will be forwarded to `upstream.1` instead of returning immediately to the client.

See all available DNS Rcodes value [here](rcode_link).

[toml_link]: https://toml.io/en
[rcode_link]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
