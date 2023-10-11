module github.com/Control-D-Inc/ctrld

go 1.20

require (
	github.com/coreos/go-systemd/v22 v22.5.0
	github.com/cuonglm/osinfo v0.0.0-20230921071424-e0e1b1e0bbbf
	github.com/frankban/quicktest v1.14.5
	github.com/fsnotify/fsnotify v1.6.0
	github.com/go-playground/validator/v10 v10.11.1
	github.com/godbus/dbus/v5 v5.1.0
	github.com/hashicorp/golang-lru/v2 v2.0.1
	github.com/illarion/gonotify v1.0.1
	github.com/insomniacslk/dhcp v0.0.0-20230407062729-974c6f05fe16
	github.com/jaytaylor/go-hostsfile v0.0.0-20220426042432-61485ac1fa6c
	github.com/josharian/native v1.1.1-0.20230202152459-5c7d0dd6ab86
	github.com/kardianos/service v1.2.1
	github.com/miekg/dns v1.1.55
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pelletier/go-toml/v2 v2.0.8
	github.com/quic-go/quic-go v0.38.0
	github.com/rs/zerolog v1.28.0
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.16.0
	github.com/stretchr/testify v1.8.3
	github.com/vishvananda/netlink v1.2.1-beta.2
	golang.org/x/net v0.10.0
	golang.org/x/sync v0.2.0
	golang.org/x/sys v0.8.1-0.20230609144347-5059a07aa46a
	golang.zx2c4.com/wireguard/windows v0.5.3
	tailscale.com v1.44.0
)

require (
	github.com/alexbrainman/sspi v0.0.0-20210105120005-909beea2cc74 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jsimonetti/rtnetlink v1.3.2 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.18 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/mdlayher/ethernet v0.0.0-20190606142754-0394541c37b7 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/raw v0.0.0-20191009151244-50f2db8cc065 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/pierrec/lz4/v4 v4.1.17 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.3.2 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/spf13/afero v1.9.5 // indirect
	github.com/spf13/cast v1.5.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/u-root/uio v0.0.0-20230305220412-3e8cd9d6bf63 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go4.org/mem v0.0.0-20220726221520-4f986261bf13 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/exp v0.0.0-20230425010034-47ecfdc1ba53 // indirect
	golang.org/x/mobile v0.0.0-20230531173138-3c911d8e3eda // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/tools v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mr-karan/doggo => github.com/Windscribe/doggo v0.0.0-20220919152748-2c118fc391f8

replace github.com/rs/zerolog => github.com/Windscribe/zerolog v0.0.0-20230503170159-e6aa153233be
