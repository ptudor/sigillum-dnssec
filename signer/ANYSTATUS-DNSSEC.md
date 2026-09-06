# AnyStatus Integration for dnssec-tudor

This service integrates with [AnyStatus](https://www.any53.com/any53/anystatus/) for "green light" monitoring. The dashboard shows whether dnssec-tudor is running, idle, or actively signing zones.

## Quick Setup

### 1. Register the Service

Create a service entry in Django admin:
https://www.any53.com/any53/admin/anystatus/serviceheartbeat/add/

| Field | Value |
|-------|-------|
| `app_key` | `dnssec-tudor` |
| `app_name` | `DNSSEC Signer` |
| `stale_threshold_minutes` | `15` |
| `dead_threshold_minutes` | `60` |

Copy the generated `api_key` for the next step.

### 2. Configure dnssec-tudor

Add to your `config.toml`:

```toml
[heartbeat]
enabled = true
api_key = "paste-your-api-key-here"
app = "dnssec-tudor"
status_url = "/dnssec/admin/"
interval_minutes = 5
```

### 3. Restart the Service

```sh
service dnssec_tudor restart
```

Check the dashboard: https://www.any53.com/any53/anystatus/

---

## Configuration Reference

```toml
[heartbeat]
# Enable heartbeat monitoring (default: false)
enabled = true

# Heartbeat endpoint URL (default shown, rarely needs changing)
url = "https://www.any53.com/any53/anystatus/heartbeat/"

# API key from AnyStatus registration (REQUIRED)
api_key = "your-api-key-here"

# Application identifier (must match registered app_key)
app = "dnssec-tudor"

# URL to admin page (shown as link on dashboard)
status_url = "/dnssec/admin/"

# Instance identifier (defaults to hostname)
# Useful when running multiple instances
instance_id = ""

# Background heartbeat interval in minutes (default: 5)
interval_minutes = 5
```

---

## Status Actions

dnssec-tudor sends these actions to indicate what it's doing:

| Action | Description |
|--------|-------------|
| `starting` | Daemon is starting up |
| `idle` | Running normally, waiting for next poll interval |
| `stopping` | Graceful shutdown in progress |

### Signing Events

| Action | Description |
|--------|-------------|
| `signing:start domain=X` | Beginning to sign zone X |
| `signing:complete domain=X serial=N` | Finished signing zone X with serial N |
| `signing:error domain=X` | Signing failed for zone X (check logs) |

### Rollover Events

| Action | Description |
|--------|-------------|
| `rollover:start domain=X type=ksk` | KSK rollover started for zone X |
| `rollover:start domain=X type=zsk` | ZSK rollover started for zone X |
| `rollover:start domain=X type=algorithm` | Algorithm rollover started for zone X |
| `rollover:complete domain=X type=ksk` | KSK rollover completed for zone X |
| `rollover:complete domain=X type=zsk` | ZSK rollover completed for zone X |
| `rollover:complete domain=X type=algorithm` | Algorithm rollover completed for zone X |

---

## Threshold Guidelines

Set your AnyStatus thresholds based on your `poll_interval`:

| poll_interval | `interval_minutes` | `stale_threshold` | `dead_threshold` |
|---------------|-------------------|-------------------|------------------|
| 1m | 5 | 15 | 60 |
| 5m (default) | 5 | 15 | 60 |
| 15m | 10 | 30 | 120 |
| 1h | 30 | 90 | 180 |

**Rule of thumb**: `stale_threshold` = 3x heartbeat interval

---

## Dashboard Colors

| Color | Meaning |
|-------|---------|
| Green | Healthy - last heartbeat within `stale_threshold` |
| Yellow | Stale - no heartbeat between stale and dead thresholds |
| Red | Dead - no heartbeat beyond `dead_threshold` |
| Gray | Unknown - never received a heartbeat |

---

## Troubleshooting

### Service shows "Unknown" (gray)

- Check that `enabled = true` in config
- Verify `api_key` and `app` match AnyStatus registration
- Check logs for heartbeat errors: `grep -i heartbeat /var/log/dnssec_tudor.log`

### Service shows "Dead" (red)

- Is the service running? `service dnssec_tudor status`
- Can it reach the internet? `curl -s https://www.any53.com/any53/anystatus/`
- Check for network/firewall issues

### Heartbeat not updating during signing

This is normal for quick operations. For zones with thousands of records, signing may take a few seconds. The `signing:complete` action will be sent when finished.

### Testing manually

```sh
curl -X POST "https://www.any53.com/any53/anystatus/heartbeat/" \
  -d "api_key=YOUR_KEY" \
  -d "app=dnssec-tudor" \
  -d "action=test"
```

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /any53/anystatus/heartbeat/` | Record heartbeat (requires api_key) |
| `GET /any53/anystatus/` | Dashboard (HTML) |
| `GET /any53/anystatus/json/` | All statuses (JSON, internal network) |

---

## See Also

- [AnyStatus Documentation](/Users/ptudor/Git/Python-Go/any53-django/ANYSTATUS.md)
- [dnssec-tudor Web Dashboard](/dnssec/admin/)
