FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
WORKDIR /app
COPY requirements.txt constraints.txt /app/
COPY deploy/server/requirements.txt /app/deploy/server/requirements.txt
RUN pip install --no-cache-dir --upgrade pip==26.2.1 && pip install --no-cache-dir -c /app/constraints.txt -r /app/deploy/server/requirements.txt
COPY src /app/src
COPY rules /app/rules
COPY prototype /app/prototype
COPY deploy/agents /app/deploy/agents
COPY deploy/aws /app/deploy/aws
COPY deploy/oci /app/deploy/oci
COPY deploy/server/bootstrap.py /app/deploy/server/bootstrap.py
COPY deploy/server/storage-report.py /app/deploy/server/storage-report.py
COPY deploy/server/enrollment-maintenance.py /app/deploy/server/enrollment-maintenance.py
USER 1000:1000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--timeout", "60", "--access-logfile", "-", "cloud_soc.portal.app:create_app()"]
