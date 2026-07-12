module github.com/ptudor/dnssec-tudor

go 1.23.0

// Enforce a minimum build toolchain patched against GO-2026-5856
// (Encrypted Client Hello PSK identity leak, fixed in Go 1.26.5).
// The go directive above remains the language floor; this pins the
// release toolchain. See REVIEW_GPT56_SOL_MAX.md R-057.
toolchain go1.26.5

require (
	github.com/miekg/dns v1.1.58
	github.com/pelletier/go-toml/v2 v2.1.1
	github.com/prometheus/client_golang v1.23.2
	github.com/spf13/cobra v1.8.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/tools v0.17.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)
