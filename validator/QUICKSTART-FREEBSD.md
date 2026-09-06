# Sigillum Validator on FreeBSD

Run Sigillum Validator on loopback and optionally expose it through your HTTPS
reverse proxy at `/dnssec/`. Commands that install files or manage the service
run as root on the target FreeBSD host.

## 1. Build

```sh
cd /path/to/validator
make build-freebsd          # writes build/sigillum-validator-freebsd-amd64
```

## 2. Install Binary

Install the artifact the build just produced (not a stale `sigillum-validator`
that may sit in the checkout) under the name the rc.d script runs:

```sh
install -m 755 build/sigillum-validator-freebsd-amd64 /usr/local/sbin/sigillum-validator
file /usr/local/sbin/sigillum-validator        # ELF 64-bit ... FreeBSD, i.e. the artifact just built
```

No wrapper script is needed: the rc.d script drops privileges itself and the
binary reads its TOML configuration directly.

## 3. Create Service User

```sh
pw useradd sigillum-validator -c "DNSSEC Validator Service" -d /nonexistent -s /usr/sbin/nologin
install -d -o sigillum-validator /var/log/sigillum-validator
```

## 4. Create the Configuration File

The binary auto-discovers `/usr/local/etc/sigillum-validator/config.toml`
(the rc.d script passes nothing else). Start from the shipped example and
keep the listener on loopback — Apache proxies to it in step 6:

```sh
mkdir -p /usr/local/etc/sigillum-validator
install -m 640 -o root -g sigillum-validator config.toml.example \
  /usr/local/etc/sigillum-validator/config.toml
```

Then set at least these keys in the installed file:

```toml
listen_addr = "127.0.0.1:8791"
root_anchors_path = "/usr/local/etc/sigillum-validator/root-anchors.json"
root_anchors_url = "https://internet.any53.com/dns/anchors/root-anchors.json"
recursive_resolver = "127.0.0.1"

[logging]
format = "json"
level = "info"
file = "/var/log/sigillum-validator/sigillum-validator.log"
```

The file is decoded strictly: a misspelled or unknown key is a startup
error, reported in the log named above (and on stderr when the binary is
run by hand with `-config /usr/local/etc/sigillum-validator/config.toml`),
so check it before the first start:

```sh
/usr/local/sbin/sigillum-validator -check -config /usr/local/etc/sigillum-validator/config.toml
```

## 5. Install rc.d Script

```sh
install -m 755 freebsd/sigillum-validator /usr/local/etc/rc.d/
```

Enable in `/etc/rc.conf`:

```sh
echo 'sigillum_validator_enable="YES"' >> /etc/rc.conf
```

## 6. Apache Configuration

Install the include file under the basename the `Include` line below uses:

```sh
install -m 644 freebsd/apache-sigillum-validator.conf /usr/local/etc/apache24/Includes/sigillum-validator.conf
```

Include in your existing HTTPS VirtualHost:

```apache
# In your existing <VirtualHost *:443> block:
Include /usr/local/etc/apache24/Includes/sigillum-validator.conf
```

Test and reload:

```sh
apachectl configtest
service apache24 reload
```

## 7. Start Service

```sh
service sigillum-validator start
```

## 8. Verify

Replace `dnssec.example.com` with the hostname configured in your HTTPS proxy.

```sh
# Check service status
service sigillum-validator status

# Test health endpoint
curl -s https://dnssec.example.com/dnssec/health | jq

# Test validation (JSON)
curl -s 'https://dnssec.example.com/dnssec/api/validate?domain=iana.org' | jq '{result, zones: [.chain[].zone]}'

# Test validation (SSE)
curl -N 'https://dnssec.example.com/dnssec/validate?domain=iana.org'

# Web UI
open https://dnssec.example.com/dnssec/
```

## Files Summary

| File | Destination |
|------|-------------|
| `build/sigillum-validator-freebsd-amd64` | `/usr/local/sbin/sigillum-validator` |
| `freebsd/sigillum-validator` | `/usr/local/etc/rc.d/sigillum-validator` |
| `freebsd/apache-sigillum-validator.conf` | `/usr/local/etc/apache24/Includes/sigillum-validator.conf` |
| `config.toml.example` | `/usr/local/etc/sigillum-validator/config.toml` |

## Logs

```sh
tail -f /var/log/sigillum-validator/sigillum-validator.log
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
service sigillum-validator status
```

### Root anchors not loading

The validator tries local file first, then falls back to URL. Ensure either:
- `/usr/local/etc/sigillum-validator/root-anchors.json` exists in the supported JSON format
- Or the URL is accessible
