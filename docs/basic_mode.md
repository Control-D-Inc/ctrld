# basic mode

`ctrld` can operate in `basic` mode, which requires no configuration file. All necessary information is provided
via command line flags, and be translated to corresponding config. `ctrld` will start with that config but do not
write anything to disk.

## Base64 encoded config

`ctrld` can read a base64 encoded config via command line flag:

```shell
ctrld run --base64_config="CltsaXN0ZW5lcl0KCiAgW2xpc3RlbmVyLjBdCiAgICBpcCA9ICIxMjcuMC4wLjEiCiAgICBwb3J0ID0gNTMKICAgIHJlc3RyaWN0ZWQgPSBmYWxzZQoKW25ldHdvcmtdCgogIFtuZXR3b3JrLjBdCiAgICBjaWRycyA9IFsiMC4wLjAuMC8wIl0KICAgIG5hbWUgPSAiTmV0d29yayAwIgoKW3Vwc3RyZWFtXQoKICBbdXBzdHJlYW0uMF0KICAgIGJvb3RzdHJhcF9pcCA9ICI3Ni43Ni4yLjExIgogICAgZW5kcG9pbnQgPSAiaHR0cHM6Ly9mcmVlZG5zLmNvbnRyb2xkLmNvbS9wMSIKICAgIG5hbWUgPSAiQ29udHJvbCBEIC0gQW50aS1NYWx3YXJlIgogICAgdGltZW91dCA9IDUwMDAKICAgIHR5cGUgPSAiZG9oIgoKICBbdXBzdHJlYW0uMV0KICAgIGJvb3RzdHJhcF9pcCA9ICI3Ni43Ni4yLjExIgogICAgZW5kcG9pbnQgPSAicDIuZnJlZWRucy5jb250cm9sZC5jb20iCiAgICBuYW1lID0gIkNvbnRyb2wgRCAtIE5vIEFkcyIKICAgIHRpbWVvdXQgPSAzMDAwCiAgICB0eXBlID0gImRvcSIK"
```

## Launch arguments

A set of arguments can be provided via command line flags.

```shell
$ ctrld run --help
Run the DNS proxy server

Usage:
  ctrld run [flags]

Flags:
      --base64_config string        base64 encoded config
  -c, --config string               Path to config file
  -d, --daemon                      Run as daemon
      --domains strings             list of domain to apply in a split DNS policy
  -h, --help                        help for run
      --listen string               listener address and port, in format: address:port
      --log string                  path to log file
      --primary_upstream string     primary upstream endpoint
      --secondary_upstream string   secondary upstream endpoint

Global Flags:
  -v, --verbose count   verbose log output, "-v" means query logging enabled, "-vv" means debug level logging enabled
```

For example:

```shell
ctrld run --listen=127.0.0.1:53 --primary_upstream=https://freedns.controld.com/p2 --secondary_upstream=8.8.8.8:53 --domains=*.company.int,*.net --log /path/to/log.log
```

Above command will be translated roughly to this config:

```toml
[service]
    log_level = "debug"
    log_path = "/path/to/log.log"

[network.0]
    name = "Network 0"
    cidrs = ["0.0.0.0/0"]

[upstream.0]
    name = "https://freedns.controld.com/p2"
    endpoint = "https://freedns.controld.com/p2"
    type = "doh"

[upstream.1]
    name = "8.8.8.8:53"
    endpoint = "8.8.8.8:53"
    type = "legacy"
	
[listener.0]
    ip = "127.0.0.1"
    port = 53

    [listener.0.policy]
        rules = [
            {"*.company.int" = ["upstream.1"]},
            {"*.net" = ["upstream.1"]},
        ]
```

`secondary_upstream`, `domains`, and `log` flags are optional.
