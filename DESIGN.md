# Kai design

## Components

- Django 5.2, PostgreSQL, local `FileField` storage
- Session authentication for web requests; expiring hashed bearer tokens for API requests
- Optional LDAP over LDAPS or StartTLS
- PostgreSQL full-text, trigram, and array search
- Separate database-queued worker for capinfos and Tshark
- Vendored CSS and JavaScript; no CDN dependency

## Access

Login is required for every capture operation. Owners manage their captures;
staff can manage all captures, tags, and lookup values. Public endpoints are
limited to authentication, health, API documentation, and autocomplete data.

## Uploads

Uploads require `.pcap` or `.pcapng`, pass structural header validation, and are
size-limited. The web process stores the file and queues an `AnalysisJob`. A
separate worker runs native tools without a shell, with time, CPU, memory, file
descriptor, and core-dump limits. Failures retry three times and do not block upload.

## Security

- Django CSRF and output escaping
- Nonce-based CSP and restrictive browser headers
- PostgreSQL-backed authentication throttling
- Legacy Rails bcrypt digest compatibility
- Signed password-reset links
- Hashed, expiring, revocable API tokens
- Security-event audit records
- Non-root containers with dropped capabilities and read-only filesystems

Production requires HTTPS, secure cookies, explicit hosts/origins, protected
secrets, restricted network egress, backups, monitoring, and image/dependency scans.
`DJANGO_PRODUCTION=1` rejects unsafe secrets, hosts, debug mode, and a missing
AGPL source link.

## Data

Core tables: `users`, `pcaps`, `tags`, `pcap_tags`, `lookup_values`,
`analysis_jobs`, `auth_failures`, and `security_events`. Lookup values start empty.

The API contract is `public/openapi.yaml`.
