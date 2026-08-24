# Stage 1: Build
FROM docker.io/library/python:3.14-slim AS build

RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y gcc libldap2-dev libsasl2-dev && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY . .

# Settings fall back to dev defaults, so collectstatic needs no real env
RUN /app/.venv/bin/python manage.py collectstatic --noinput

# Stage 2: Runtime
FROM docker.io/library/python:3.14-slim

# tshark provides capinfos for metadata extraction; postgresql-client
# provides pg_isready for the entrypoint. psycopg ships its own libpq.
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y tshark postgresql-client && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --system kai && \
    useradd --system --gid kai --create-home kai

WORKDIR /app

COPY --from=build /app /app

RUN chmod -R a+rX /app && \
    mkdir -p /app/storage && \
    chown -R kai:kai /app/storage

USER kai

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 3022

ENTRYPOINT ["/bin/bash", "/app/bin/container-entrypoint"]
CMD ["web"]
