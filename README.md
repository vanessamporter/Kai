# Kai

Authenticated pcap storage, search, tagging, and bounded Tshark analysis.

## Run locally

Requires Python 3.12+, `uv`, PostgreSQL, and optionally Tshark.

```bash
make setup
make server  # terminal 1
make worker  # terminal 2
```

Open <http://localhost:3022>. Use `make help` for other commands.

## Test

```bash
uv run pytest
uv run ruff check .
uv run ruff format .
```

## Containers

```bash
podman compose up --build
```

Compose runs PostgreSQL, the web app, and an isolated analysis worker. Production
examples are in `deploy/`; configure TLS, hosts, secrets, SMTP, and optional LDAP
with `deploy/env/app.env.example`.

## Configuration

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL URL |
| `SECRET_KEY_BASE` | Django signing secret |
| `KAI_STORAGE_PATH` | Capture storage path |
| `DJANGO_PRODUCTION` | Enable fail-closed production checks |
| `DJANGO_ALLOWED_HOSTS` | Allowed hosts |
| `MAX_PCAP_UPLOAD_BYTES` | Upload limit |
| `LDAP_SERVER_URI` | Optional LDAPS/StartTLS directory |
| `SOURCE_CODE_URL` | AGPL source repository URL |

API documentation is served at `/api/docs`; the source is `public/openapi.yaml`.
Architecture and security notes are in `DESIGN.md`.

## License

GNU Affero General Public License v3. See `LICENSE`.
