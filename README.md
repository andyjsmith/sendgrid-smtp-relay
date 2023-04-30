# SendGrid SMTP Relay

SMTP server that relays messages to SendGrid via its API.

This does NOT use authentication or encryption. It is designed only for use on a single host or LAN.

## Requirements

- Python 3
- Docker

## Running

```bash
docker compose build
docker compose up -d
```

Or for older Docker Compose versions:

```bash
docker-compose build
docker-compose up -d
```

Without Docker:

```bash
# Set your environment variables first
python3 server.py
```

## Configuration

You need to specify configuration options using enviroment variables. Use the docker-compose.yml as a template.

- SENDGRID_API_KEY (required): Your SendGrid API key with Mail Send permissions
- DOMAIN_FROM_ALLOWLIST: Comma-separated list of domains that are allowed to be in the FROM field.
- DOMAIN_TO_ALLOWLIST: Comma-separated list of domains that are allowed to be in the TO field.
- LOGLEVEL: Log level for printed messages. One of DEBUG, INFO, WARNING, ERROR, CRITICAL. Default: INFO.
- HOSTNAME: Hostname to bind to. No need to change when running with Docker, update the "ports" option in docker-compose.yml instead. Default: 127.0.0.1.
- PORT: Port to bind to. No need to change when running with Docker, update the "ports" option in docker-compose.yml instead. Default: 25.
