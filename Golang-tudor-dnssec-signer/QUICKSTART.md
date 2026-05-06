# QUICKSTART: dnssec-tudor

Get DNSSEC signing working in 10 minutes.

## Prerequisites

- Go 1.21+ (for building)
- An authoritative DNS server (NSD, BIND, Knot)
- Access to your domain's registrar (for DS records)

## Step 1: Build

```bash
cd Golang-tudor-dnssec-signer
make build
sudo cp dnssec-tudor /usr/local/bin/
```

## Step 2: Create Directories

```bash
sudo mkdir -p /etc/dnssec-tudor
sudo mkdir -p /var/lib/dnssec-tudor/{keys,signed}

# Optional: dedicated user
sudo useradd -r -s /bin/false dnssec-tudor
sudo chown -R dnssec-tudor:dnssec-tudor /var/lib/dnssec-tudor
sudo chmod 700 /var/lib/dnssec-tudor/keys
```

## Step 3: Create Configuration

```bash
sudo tee /etc/dnssec-tudor/config.toml << 'EOF'
output_dir = "/var/lib/dnssec-tudor/signed"
data_dir = "/var/lib/dnssec-tudor"
poll_interval = "5m"

[dnssec]
algorithm = "ED25519"
ksk_lifetime = "5y"
zsk_lifetime = "90d"
signature_validity = "14d"
signature_refresh = "3d"
nsec_version = "nsec3"

[web]
enabled = false

[zones]
# Add your zones here after step 4

[hooks]
post_sign = "systemctl reload nsd"  # or: nsd-control reload
EOF
```

## Step 4: Add Your First Zone

Make sure your unsigned zone file exists and is valid:

```bash
# Check your zone file
nsd-checkzone example.com /etc/nsd/zones/example.com.zone
```

Add the zone to dnssec-tudor:

```bash
sudo dnssec-tudor add example.com /etc/nsd/zones/example.com.zone \
  --config /etc/dnssec-tudor/config.toml
```

Output:
```
Domain example.com added successfully.

Add the following DS record to your registrar:
;; DS records for example.com
;; Key Tag: 12345, Algorithm: ED25519

;; Full DS record (digest type 2, SHA-256):
example.com.  3600  IN  DS  12345 15 2 ABC123...

;; Registrar format:
Key Tag: 12345
Algorithm: 15 (ED25519)
Digest Type: 2 (SHA-256)
Digest: ABC123...
```

## Step 5: Update NSD Configuration

Point NSD to the signed zone:

```bash
# /etc/nsd/nsd.conf
zone:
    name: "example.com"
    zonefile: "/var/lib/dnssec-tudor/signed/example.com.zone.signed"
```

Reload NSD:
```bash
sudo systemctl reload nsd
```

## Step 6: Add DS Record to Registrar

Go to your registrar's DNS settings and add the DS record. The exact process varies:

**Common registrars:**
- **Cloudflare**: DNS → DNSSEC → Enable → Enter DS record
- **Namecheap**: Advanced DNS → DNSSEC → Add DS record
- **GoDaddy**: DNS Management → DNSSEC → Add
- **Gandi**: DNSSEC tab → Add DS record

Enter the values from step 4:
- Key Tag: `12345`
- Algorithm: `15` (ED25519)
- Digest Type: `2` (SHA-256)
- Digest: `ABC123...`

## Step 7: Wait for Propagation

DS records can take up to 48 hours to propagate. Check status:

```bash
# Check if DS is published
dig DS example.com +short

# Verify DNSSEC chain
dig +dnssec example.com

# Online validators
# https://dnssec-debugger.verisignlabs.com/
# https://dnsviz.net/
```

## Step 8: Run as Daemon

### Option A: Systemd Service

```bash
sudo tee /etc/systemd/system/dnssec-tudor.service << 'EOF'
[Unit]
Description=DNSSEC Tudor Signing Daemon
After=network.target

[Service]
Type=simple
User=dnssec-tudor
ExecStart=/usr/local/bin/dnssec-tudor serve --config /etc/dnssec-tudor/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable dnssec-tudor
sudo systemctl start dnssec-tudor
```

### Option B: Run in Screen/Tmux

```bash
sudo -u dnssec-tudor dnssec-tudor serve --config /etc/dnssec-tudor/config.toml
```

## Step 9: Verify Everything Works

```bash
# Check daemon status
sudo systemctl status dnssec-tudor

# Check zone status
dnssec-tudor status --config /etc/dnssec-tudor/config.toml

# Verify signatures
dig +dnssec example.com @localhost
```

## Adding More Zones

1. Add zone to config:
```toml
[zones."another.com"]
path = "/etc/nsd/zones/another.com.zone"
```

2. Reload daemon:
```bash
sudo systemctl reload dnssec-tudor  # or kill -HUP <pid>
```

3. Get DS record and add to registrar:
```bash
dnssec-tudor ds another.com --config /etc/dnssec-tudor/config.toml
```

## Troubleshooting

### "Zone file does not exist"
Check the path in your config matches your actual zone file location.

### "Algorithm not supported by registrar"
Switch to ECDSAP256SHA256 in config.toml — it has wider support than ED25519.

### Signatures expiring
The daemon should re-sign automatically. Check logs:
```bash
journalctl -u dnssec-tudor -f
```

### DNSSEC validation failing
1. Verify DS record is published: `dig DS example.com +short`
2. Check DS matches your KSK: `dnssec-tudor ds example.com`
3. Use online debugger: https://dnsviz.net/

## Next Steps

- Enable the web UI for easier monitoring
- Set up monitoring alerts on `/healthz` endpoint
- Read about KSK rollover in the README (it's semi-automatic)

## Quick Reference

| Command | Description |
|---------|-------------|
| `dnssec-tudor serve` | Run daemon |
| `dnssec-tudor sign` | One-shot sign all zones |
| `dnssec-tudor status` | Show status JSON |
| `dnssec-tudor ds <domain>` | Get DS record for registrar |
| `dnssec-tudor add <domain> <path>` | Add new domain |
| `dnssec-tudor rollover start <domain>` | Start KSK rollover |
