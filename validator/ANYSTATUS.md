# AnyStatus Integration for sigillum-validator

This service integrates with [AnyStatus](https://www.any53.com/any53/anystatus/) for "green light" monitoring. The dashboard shows whether sigillum-validator is running and healthy.

## Quick Setup

### 1. Register the Service

Create a service entry in Django admin:
https://www.any53.com/any53/admin/anystatus/serviceheartbeat/add/

| Field | Value |
|-------|-------|
| `app_key` | `sigillum-validator` |
| `app_name` | `DNSSEC Validator` |
| `stale_threshold_minutes` | `15` |
| `dead_threshold_minutes` | `60` |

Copy the generated `api_key` for the next step.

### 2. Configure sigillum-validator

Add to your environment file or `.env`:

```bash
HEARTBEAT_ENABLED=true
HEARTBEAT_API_KEY=paste-your-api-key-here
HEARTBEAT_APP=sigillum-validator
HEARTBEAT_STATUS_URL=/
HEARTBEAT_INTERVAL_MINUTES=5
```

### 3. Restart the Service

```sh
service sigillum-validator restart
```

Check the dashboard: https://www.any53.com/any53/anystatus/

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `HEARTBEAT_ENABLED` | `false` | Enable heartbeat monitoring |
| `HEARTBEAT_URL` | `https://www.any53.com/any53/anystatus/heartbeat/` | Heartbeat endpoint (rarely needs changing) |
| `HEARTBEAT_API_KEY` | (none) | API key from AnyStatus registration (REQUIRED) |
| `HEARTBEAT_APP` | `sigillum-validator` | Application identifier (must match registered app_key) |
| `HEARTBEAT_STATUS_URL` | (none) | URL to status page (shown as link on dashboard) |
| `HEARTBEAT_INSTANCE_ID` | (hostname) | Instance identifier for multiple instances |
| `HEARTBEAT_INTERVAL_MINUTES` | `5` | Background heartbeat interval (integer minutes) |

---

## Status Actions

sigillum-validator sends these actions to indicate what it's doing:

| Action | Description |
|--------|-------------|
| `starting` | Server is starting up |
| `idle` | Running normally, waiting for requests |
| `running` | Currently processing validation requests |
| `stopping` | Graceful shutdown in progress |

### Validation Events

| Action | Description |
|--------|-------------|
| `validate:start` | Beginning domain validation |
| `validate:complete` | Finished validating a domain |

---

## Threshold Guidelines

Set your AnyStatus thresholds based on expected activity:

| Scenario | `HEARTBEAT_INTERVAL_MINUTES` | `stale_threshold` | `dead_threshold` |
|----------|---------------------|-------------------|------------------|
| Active (frequent validations) | 5m | 15 | 60 |
| Moderate | 10m | 30 | 120 |
| Low activity | 15m | 45 | 180 |

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

- Check that `HEARTBEAT_ENABLED=true` in config
- Verify `HEARTBEAT_API_KEY` and `HEARTBEAT_APP` match AnyStatus registration
- Check logs for heartbeat errors: `grep -i heartbeat /var/log/sigillum-validator/sigillum-validator.log`

### Service shows "Dead" (red)

- Is the service running? `service sigillum-validator status`
- Can it reach the internet? `curl -s https://www.any53.com/any53/anystatus/`
- Check for network/firewall issues

### Testing manually

```sh
curl -X POST "https://www.any53.com/any53/anystatus/heartbeat/" \
  -d "api_key=YOUR_KEY" \
  -d "app=sigillum-validator" \
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
- [DNSSEC Validator Dashboard](/)
