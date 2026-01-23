# DNSSEC Validator - FreeBSD Quick Start

Deploy the DNSSEC validator at `/dnssec/` on www.any53.com and internet.any53.com.

## 1. Build

```sh
cd /path/to/Golang-dnssec-validator
make build-freebsd
```

## 2. Install Binary and Wrapper

```sh
install -m 755 dnssec-validator /usr/local/sbin/
install -m 755 freebsd/dnssec-validator.sh /usr/local/sbin/
```

## 3. Create Service User

```sh
pw useradd dnssec-validator -c "DNSSEC Validator Service" -d /nonexistent -s /usr/sbin/nologin
install -d -o dnssec-validator /var/log/tudordns
```

## 4. Create Environment File

```sh
mkdir -p /usr/local/etc/tudordns
cat > /usr/local/etc/tudordns/dnssec-validator.env << 'EOF'
LISTEN_ADDR=127.0.0.1:8791
ROOT_ANCHORS_PATH=/var/www/internet.any53.com/dns/anchors/root-anchors.json
ROOT_ANCHORS_URL=https://internet.any53.com/dns/anchors/root-anchors.json
QUERY_TIMEOUT=5s
TOTAL_TIMEOUT=30s
MAX_CONCURRENT=10
RATE_LIMIT_PER_SEC=10
RATE_LIMIT_BURST=30
LOG_LEVEL=info
LOG_FORMAT=json
LOG_FILE=/var/log/tudordns/dnssec-validator.log
SHUTDOWN_TIMEOUT_SECONDS=30
EOF

chown root:dnssec-validator /usr/local/etc/tudordns/dnssec-validator.env
chmod 640 /usr/local/etc/tudordns/dnssec-validator.env
```

## 5. Install rc.d Script

```sh
install -m 755 freebsd/dnssec_validator /usr/local/etc/rc.d/
```

Enable in `/etc/rc.conf`:

```sh
echo 'dnssec_validator_enable="YES"' >> /etc/rc.conf
```

## 6. Apache Configuration

Copy the include file:

```sh
install -m 644 freebsd/apache-dnssec-validator.conf /usr/local/etc/apache24/Includes/
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
| `dnssec-validator` | `/usr/local/sbin/dnssec-validator` |
| `freebsd/dnssec-validator.sh` | `/usr/local/sbin/dnssec-validator.sh` |
| `freebsd/dnssec_validator` | `/usr/local/etc/rc.d/dnssec_validator` |
| `freebsd/apache-dnssec-validator.conf` | `/usr/local/etc/apache24/Includes/dnssec-validator.conf` |
| `.env` | `/usr/local/etc/tudordns/dnssec-validator.env` |

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
