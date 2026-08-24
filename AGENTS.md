# Repository guidance

These instructions apply to any coding assistant or contributor.

## Requirements

- Keep runtime assets local; do not add CDN dependencies.
- Update `README.md`, `DESIGN.md`, or `public/openapi.yaml` only when behavior changes.
- Keep comments and documentation brief and current.
- Preserve unrelated user changes.
- Use `apply_patch` for manual edits.

## Validation

Run before handoff:

```bash
uv run ruff check .
uv run ruff format .
uv run pytest
```

## Commands

```bash
make setup
make server
make compose-up
```

## Structure

- `config/`: Django settings and entry points
- `kai/`: models, views, security, analysis, templates, and static assets
- `tests/`: pytest suite
- `deploy/`: production examples
- `public/openapi.yaml`: API contract

## Commits

Use an imperative subject under 72 characters. Explain why in the body when needed.
