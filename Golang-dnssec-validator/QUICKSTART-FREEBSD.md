# DNSSEC Validator - FreeBSD Quick Start

Deploy the DNSSEC validator at `/dnssec/` on www.any53.com and internet.any53.com.

## 1. Build

```sh
cd /path/to/Golang-dnssec-validator
make build-freebsd          # writes build/dnssec-validator-freebsd-amd64
```

## 2. Install Binary

Install the artifact the build just produced (not a stale `dnssec-validator`
that may sit in the checkout) under the name the rc.d script runs:

```sh
install -m 755 build/dnssec-validator-freebsd-amd64 /usr/local/sbin/dnssec-validator
file /usr/local/sbin/dnssec-validator        # ELF 64-bit ... FreeBSD, i.e. the artifact just built
```

No wrapper script is needed: the rc.d script drops privileges itself and the
binary reads its TOML configuration directly.

## 3. Create Service User

```sh
pw useradd dnssec-validator -c "DNSSEC Validator Service" -d /nonexistent -s /usr/sbin/nologin
install -d -o dnssec-validator /var/log/tudordns
```

## 4. Create the Configuration File

The binary auto-discovers `/usr/local/etc/tudordns/dnssec-validator.toml`
(the rc.d script passes nothing else). Start from the shipped example and
keep the listener on loopback — Apache proxies to it in step 6:

```sh
mkdir -p /usr/local/etc/tudordns
install -m 640 -o root -g dnssec-validator dnssec-validator.toml.example \
  /usr/local/etc/tudordns/dnssec-validator.toml
```

Then set at least these keys in the installed file:

```toml
listen_addr = "127.0.0.1:8791"
root_anchors_path = "/var/www/internet.any53.com/dns/anchors/root-anchors.json"
root_anchors_url = "https://internet.any53.com/dns/anchors/root-anchors.json"
recursive_resolver = "127.0.0.1"

[logging]
format = "json"
level = "info"
file = "/var/log/tudordns/dnssec-validator.log"
```

The file is decoded strictly: a misspelled or unknown key is a startup
error, reported in the log named above (and on stderr when the binary is
run by hand with `-config /usr/local/etc/tudordns/dnssec-validator.toml`),
so check the log after the first start in step 5.

## 5. Install rc.d Script

```sh
install -m 755 freebsd/dnssec_validator /usr/local/etc/rc.d/
```

Enable in `/etc/rc.conf`:

```sh
echo 'dnssec_validator_enable="YES"' >> /etc/rc.conf
```

## 6. Apache Configuration

Install the include file under the basename the `Include` line below uses:

```sh
install -m 644 freebsd/apache-dnssec-validator.conf /usr/local/etc/apache24/Includes/dnssec-validator.conf
```

Include in your VirtualHost (add to existing www.any53.com and internet.any53.com configs):

```apache
# In your existing <VirtualHost *:443> block:
Include /usr/local/etc/apache24/Includes/dnssec-validator.conf
```

Test and reload:

```sh
apachectl configtest
service apache24 reload
```

## 7. Start Service

```sh
service dnssec_validator start
```

## 8. Verify

```sh
# Check service status
service dnssec_validator status

# Test health endpoint
curl -s https://www.any53.com/dnssec/health | jq

# Test validation (JSON)
curl -s 'https://www.any53.com/dnssec/api/validate?domain=iana.org' | jq '{result, zones: [.chain[].zone]}'

# Test validation (SSE)
curl -N 'https://www.any53.com/dnssec/validate?domain=iana.org'

# Web UI
open https://www.any53.com/dnssec/
```

## Files Summary

| File | Destination |
|------|-------------|
| `build/dnssec-validator-freebsd-amd64` | `/usr/local/sbin/dnssec-validator` |
| `freebsd/dnssec_validator` | `/usr/local/etc/rc.d/dnssec_validator` |
| `freebsd/apache-dnssec-validator.conf` | `/usr/local/etc/apache24/Includes/dnssec-validator.conf` |
| `dnssec-validator.toml.example` | `/usr/local/etc/tudordns/dnssec-validator.toml` |

## Logs

```sh
tail -f /var/log/tudordns/dnssec-validator.log
```

## Troubleshooting

### SSE not streaming

Ensure Apache has:
- `mod_proxy` loaded
- `mod_proxy_http` loaded
- `mod_headers` loaded

Check the include file has `proxy-nokeepalive` and `no-gzip` settings.

### 503 Service Unavailable

Check if the service is running:

```sh
sockstat -l | grep 8791
service dnssec_validator status
```

### Root anchors not loading

The validator tries local file first, then falls back to URL. Ensure either:
- `/var/www/internet.any53.com/dns/anchors/root-anchors.json` exists (from internet-mirror)
- Or the URL is accessible
