# QUICKSTART: sigillum-signer

Get DNSSEC signing working in 10 minutes.

## Prerequisites

- Go 1.27.1 (the release toolchain in `../.go-version`)
- An authoritative DNS server (NSD, BIND, Knot)
- Access to your domain's registrar (for DS records)

## Step 1: Build

```bash
cd signer
make build
sudo cp sigillum-signer /usr/local/bin/
```

## Step 2: Create Directories

The service runs unprivileged as the `sigillum-signer` account (the systemd
unit in step 8 sets `User=sigillum-signer`, so the account is required, not
optional). It must be able to read the unsigned zones, write keys, state and
signed output, and NSD must be able to read the signed output:

```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/sigillum-signer sigillum-signer
sudo mkdir -p /etc/sigillum-signer
sudo install -d -o sigillum-signer -g sigillum-signer -m 750 /var/lib/sigillum-signer
sudo install -d -o sigillum-signer -g sigillum-signer -m 700 /var/lib/sigillum-signer/keys
sudo install -d -o sigillum-signer -g nsd -m 750 /var/lib/sigillum-signer/signed   # NSD reads here
# Unsigned zones: readable by the service account (adjust to where they live)
sudo chgrp -R sigillum-signer /etc/nsd/zones && sudo chmod -R g+rX /etc/nsd/zones
```

The signer must also be able to tell NSD to reload without a password. Do not
give the account a general `sudo` or `systemctl` grant; allow exactly the one
reload command it runs from the hook:

```bash
sudo tee /etc/sudoers.d/sigillum-signer << 'EOF'
sigillum-signer ALL=(root) NOPASSWD: /usr/sbin/nsd-control reload
EOF
sudo chmod 440 /etc/sudoers.d/sigillum-signer
sudo -u sigillum-signer sudo -n /usr/sbin/nsd-control reload   # must succeed non-interactively
```

(An alternative with no sudo at all: make the account a member of the group
that may read NSD's control key files and socket, so `nsd-control reload`
works directly; whichever you choose, the non-interactive test above must
pass before the daemon is started.)

## Step 3: Create Configuration

```bash
sudo tee /etc/sigillum-signer/config.toml << 'EOF'
output_dir = "/var/lib/sigillum-signer/signed"
data_dir = "/var/lib/sigillum-signer"
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
# Exactly the command allowed in /etc/sudoers.d/sigillum-signer (step 2). The
# hook must succeed: a signed zone counts as published only after it does.
post_sign_cmd = ["/usr/bin/sudo", "-n", "/usr/sbin/nsd-control", "reload"]
EOF
```

## Step 4: Add Your First Zone

Make sure your unsigned zone file exists and is valid:

```bash
# Check your zone file
nsd-checkzone example.com /etc/nsd/zones/example.com.zone
```

Add the zone to sigillum-signer:

```bash
sudo sigillum-signer add example.com /etc/nsd/zones/example.com.zone \
  --config /etc/sigillum-signer/config.toml
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
    zonefile: "/var/lib/sigillum-signer/signed/example.com.zone.signed"
```

Reload NSD:
```bash
sudo systemctl reload nsd
```

## Step 6: Add DS Record to Registrar

Go to your registrar's DNS settings and add the DS record. The exact process varies:

**Common registrars:**
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
sudo tee /etc/systemd/system/sigillum-signer.service << 'EOF'
[Unit]
Description=DNSSEC Tudor Signing Daemon
After=network.target

[Service]
Type=simple
User=sigillum-signer
ExecStart=/usr/local/bin/sigillum-signer serve --config /etc/sigillum-signer/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable sigillum-signer
sudo systemctl start sigillum-signer
```

### Option B: Run in Screen/Tmux

```bash
sudo -u sigillum-signer sigillum-signer serve --config /etc/sigillum-signer/config.toml
```

## Step 9: Verify Everything Works

```bash
# Check daemon status
sudo systemctl status sigillum-signer

# Check zone status
sigillum-signer status --config /etc/sigillum-signer/config.toml

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
sudo systemctl reload sigillum-signer  # or kill -HUP <pid>
```

3. Get DS record and add to registrar:
```bash
sigillum-signer ds another.com --config /etc/sigillum-signer/config.toml
```

## Troubleshooting

### "Zone file does not exist"
Check the path in your config matches your actual zone file location.

### "Algorithm not supported by registrar"
Do **not** just change `algorithm` in config.toml: the setting only applies to
keys generated in the future, existing zones keep their keys, and an ordinary
KSK rollover always keeps a zone's current algorithm. Migrate the zone with
the supported rollover, which publishes both algorithms until the new DS is
live and the caches have drained:

```bash
sigillum-signer rollover algorithm example.com ECDSAP256SHA256 --config /etc/sigillum-signer/config.toml
# publish the printed DS at the registrar, wait for it to propagate, then:
sigillum-signer rollover complete example.com --config /etc/sigillum-signer/config.toml
# later, when status asks for it, remove the old DS; retirement is automatic
```

Set `algorithm = "ECDSAP256SHA256"` in config.toml as well so zones added
later start on the algorithm your registrar accepts.

### Signatures expiring
The daemon should re-sign automatically. Check logs:
```bash
journalctl -u sigillum-signer -f
```

### DNSSEC validation failing
1. Verify DS record is published: `dig DS example.com +short`
2. Check DS matches your KSK: `sigillum-signer ds example.com`
3. Use online debugger: https://dnsviz.net/

## Next Steps

- Enable the web UI for easier monitoring
- Set up monitoring alerts on `/healthz` endpoint
- Read about KSK rollover in the README (it's semi-automatic)

## Quick Reference

| Command | Description |
|---------|-------------|
| `sigillum-signer serve` | Run daemon |
| `sigillum-signer sign` | One-shot sign all zones |
| `sigillum-signer status` | Show status JSON |
| `sigillum-signer ds <domain>` | Get DS record for registrar |
| `sigillum-signer add <domain> <path>` | Add new domain |
| `sigillum-signer rollover start <domain>` | Start KSK rollover |
