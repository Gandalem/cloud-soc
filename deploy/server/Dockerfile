FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
WORKDIR /app
COPY requirements.txt constraints.txt /app/
COPY deploy/server/requirements.txt /app/deploy/server/requirements.txt
RUN pip install --no-cache-dir --timeout 30 --retries 3 --upgrade pip==26.2.1 && pip install --no-cache-dir --timeout 30 --retries 3 -c /app/constraints.txt -r /app/deploy/server/requirements.txt
COPY src /app/src
COPY rules /app/rules
COPY prototype /app/prototype
COPY deploy/agents /app/deploy/agents
COPY deploy/aws /app/deploy/aws
COPY deploy/oci /app/deploy/oci
COPY deploy/server /app/deploy/server
# Normalize public source permissions even from a restrictive build archive.
# Runtime databases, certificates and secrets are mounted separately afterwards.
RUN find /app/src /app/rules /app/prototype /app/deploy -type d -exec chmod 755 {} + \
    && find /app/src /app/rules /app/prototype /app/deploy -type f -exec chmod 644 {} +
USER 1000:1000
# Do not log URLs/query strings, Basic usernames, Referer or request bodies.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--timeout", "60", "--access-logfile", "-", "--access-logformat", "%(m)s %(s)s %(L)s", "cloud_soc.portal.app:create_app()"]
