module github.com/ptudor/sigillum-dnssec/validator

go 1.25.0

// Use the release toolchain from .go-version when Go selects a toolchain.
// The go directive above records the minimum required by dependencies.
toolchain go1.27.1

require (
	github.com/miekg/dns v1.1.73
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/prometheus/client_golang v1.24.1
	golang.org/x/net v0.58.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.71.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
