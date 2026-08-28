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

## Group accounts

Kai uses email addresses as usernames. In the recommended group configuration,
visitors can request access but cannot log in until a staff user approves the
request from **Users**. Staff may also create active accounts directly.

Create the first administrator after starting Kai:

```bash
podman compose exec app python manage.py createsuperuser --email admin@example.com
```

Existing users and captures are not changed when approval mode is enabled.
Passwords are stored only as bcrypt hashes. Configure SMTP before relying on
password resets.

## Production checklist

- Set `DJANGO_PRODUCTION=1` and use a unique `SECRET_KEY_BASE` and database password.
- Put Kai behind an HTTPS reverse proxy and enable the secure cookie/proxy settings
  shown in `deploy/env/app.env.example`.
- Set explicit allowed hosts and CSRF origins.
- Configure SMTP and test password resets.
- Create the first administrator, then keep signup approval enabled.
- Back up both PostgreSQL and the capture-storage volume.

The development `compose.yaml` deliberately uses example credentials and must not
be exposed directly to the internet.

## Backups

With the Compose stack running:

```bash
make backup                         # writes to ./backups
BACKUP_DIR=/safe/kai make backup   # choose another destination
```

Each timestamped backup contains `database.dump`, `pcaps.tar.gz`, and checksums.
Copy backups off the Kai server and test restoration regularly. Restore into a
stopped application using `pg_restore` for the database and extract
`pcaps.tar.gz` into `KAI_STORAGE_PATH`. Never restore over a running worker.

## Configuration

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL URL |
| `SECRET_KEY_BASE` | Django signing secret |
| `KAI_STORAGE_PATH` | Capture storage path |
| `DJANGO_PRODUCTION` | Enable fail-closed production checks |
| `DJANGO_ALLOWED_HOSTS` | Allowed hosts |
| `ALLOW_PUBLIC_SIGNUP` | Show the access-request form |
| `REQUIRE_SIGNUP_APPROVAL` | Keep requested accounts inactive until staff approval |
| `MAX_PCAP_UPLOAD_BYTES` | Upload limit |
| `LDAP_SERVER_URI` | Optional LDAPS/StartTLS directory |
| `SOURCE_CODE_URL` | AGPL source repository URL |

API documentation is served at `/api/docs`; the source is `public/openapi.yaml`.
Architecture and security notes are in `DESIGN.md`.

## License

GNU Affero General Public License v3. See `LICENSE`.
