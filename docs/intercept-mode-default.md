# Intercept Mode Default

On the supported desktop platforms, macOS and Windows desktop (workstation)
editions, a new ctrld installation runs in DNS intercept mode (`dns`) unless
you select a mode explicitly. Everywhere else, Windows Server included, it
keeps interface DNS mode, which sets ctrld's listener as the DNS server of the
network interfaces. An existing installation keeps the mode it had: upgrading
never switches a Standard (interface DNS) install to intercept mode. See
[Upgrades](#upgrades).

Windows Server is excluded on purpose. A server, and a domain controller
running its own DNS server in particular, is not switched to intercept mode by
default. Intercept mode still works there when selected explicitly.

This applies to a service that `ctrld-client start` installs and to `ctrld-client run` in
the foreground alike. See [DNS Intercept Mode](dns-intercept-mode.md) for what
intercept mode does.

## Precedence

The effective mode is the first of these that is set:

1. `--intercept-mode` on the command line, or in the service's arguments.
2. `service.intercept_mode` in the configuration the service runs with:
   `ctrld.toml`, a `--base64_config`, or a Control D custom configuration.
3. The default: `dns` on macOS and Windows desktop editions; interface DNS
   mode elsewhere, Windows Server included. An installed service that predates
   the default is the exception, see [Upgrades](#upgrades).

`off` is a selection like `dns` and `hard`, not an absence of one. At either
explicit level it stops the lookup and selects interface DNS mode, including
over a persisted `intercept_mode = "dns"`.

| `--intercept-mode` | `service.intercept_mode` | macOS / Windows desktop | Windows Server | Linux and others |
|---|---|---|---|---|
| unset | unset | `dns` (default)² | interface DNS mode | interface DNS mode |
| unset | `dns` / `hard` | that mode | that mode | that mode¹ |
| unset | `off` | interface DNS mode | interface DNS mode | interface DNS mode |
| `dns` / `hard` | any | that mode | that mode | that mode¹ |
| `off` | any | interface DNS mode | interface DNS mode | interface DNS mode |

² For a fresh install or a foreground run. An installed service that predates
the default keeps interface DNS mode, see [Upgrades](#upgrades).

¹ Intercept mode is not supported outside Windows and macOS, so an explicit
`dns` or `hard` there fails to start intercept, as before. An unset mode never
tries: those platforms do not log an intercept-start failure just because the
default changed.

Desktop versus server follows `ctrld.IsDesktopPlatform`, which ctrld already
uses elsewhere: on Windows it is the workstation product type
(`VER_NT_WORKSTATION`), so Windows Server and domain controllers are not
desktop platforms.
iOS is not a desktop platform here either, although it builds ctrld's macOS
code: it has no pf to intercept with.

The default also keeps interface DNS mode for a configuration that cannot run
in intercept mode. On macOS that is any `os` or untyped upstream: pf would
redirect ctrld's own port-53 queries to it back to ctrld. Such a configuration
worked in interface DNS mode and keeps doing so; the service log says why the
default was not used. Selecting `dns` or `hard` explicitly for it still fails
to start intercept, as before.

The service decides the default itself, on every start, against the
configuration it runs with. In Control D mode (`--cd`) that is the resolver's
configuration it fetches, so an `os` upstream or an `intercept_mode` in a
custom configuration counts, including one added after installation.

## Opting out

Use interface DNS mode explicitly:

```shell
# Windows (Admin Shell)
ctrld-client.exe start --intercept-mode off --cd RESOLVER_ID_HERE

# macOS
sudo ctrld-client start --intercept-mode off --cd RESOLVER_ID_HERE
```

On an installed service, `ctrld-client start --intercept-mode off` with no other
arguments switches the existing service to interface DNS mode, keeping its
other arguments.

The selection is stored in two places, so it survives restarts and upgrades:

- in the service's arguments, as `--intercept-mode off`;
- in `ctrld.toml`, as `intercept_mode = "off"`.

Earlier builds cleared `intercept_mode` when switching to `off`. That no longer
works as an opt-out: an unset value now means the platform default, so
switching to `off` writes `off`. Older builds read `off` the same way, so a
downgrade keeps interface DNS mode too.

## Upgrades

Only a fresh installation gets the `dns` default. An existing Standard
(interface DNS) installation stays in Standard mode across upgrades, whichever
path upgrades it.

To tell the two apart, `ctrld-client start` marks the services it installs, in the
service's arguments, when no mode is selected:

- A fresh install records `--intercept-mode-default=true`, an internal flag.
  It ranks lowest: the service applies the default only if neither
  `--intercept-mode` nor `service.intercept_mode` selects a mode, against the
  configuration it fetched.
- A reinstall over an existing service keeps what that service recorded, its
  mode or the marker. If it recorded neither, it was installed in Standard mode
  before this default, and the reinstall records `--intercept-mode off`, unless
  `service.intercept_mode` selects a mode.
- Platforms without the `dns` default record nothing, as before.

Older ctrld builds ignore flags they do not know in the service's arguments,
so the marker is safe if a device is downgraded.

An installed service with neither a mode nor the marker therefore predates
the default. It keeps interface DNS mode when the new binary runs it, and the
service log says why. That covers upgrades that rewrite nothing, such as
`ctrld-client upgrade` run by an older binary, which swaps the binary and restarts the
service with its existing arguments. A foreground `ctrld-client run` with no mode
selected uses the default.

The macOS package pins such a service explicitly when it upgrades it with a
profile that has no `InterceptMode`: it runs `ctrld-client start --intercept-mode
off`, the same as for a `standard` profile. See
[macOS MDM Package](macos-pkg-mdm.md).

To move an existing Standard installation to intercept mode, select it
explicitly with `ctrld-client start --intercept-mode dns`.

The Control D installer and dashboard should generate `--intercept-mode off` for
a device where Standard mode is chosen, so a fresh install never gets intercept
mode against that choice.

## Where the mode is reported

- `ctrld-client start` output: `DNS intercept mode active ...` once the service runs
  in intercept mode, followed, when the default selected it, by how to switch
  to interface DNS mode. A reinstall over a Standard install prints `Existing
  service selects no intercept mode; keeping interface DNS mode
  (--intercept-mode off)`.
- The service log, at startup: `Intercept mode enabled via config` when the
  configuration set the mode, `Intercept mode "dns" is the default on this
  platform; ...` when the default applied, or `Intercept mode default not
  applied; using interface DNS mode` with the reason, for a service that
  predates the default or a configuration that cannot run in intercept mode.
- The log header field `intercept_mode`, which reads `off` for interface DNS
  mode.
