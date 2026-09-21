FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
WORKDIR /app
COPY requirements.txt /app/requirements.txt
COPY deploy/server/requirements.txt /app/deploy/server/requirements.txt
RUN pip install --no-cache-dir -r /app/deploy/server/requirements.txt
COPY src /app/src
COPY prototype /app/prototype
COPY deploy/agents /app/deploy/agents
COPY deploy/server/bootstrap.py /app/deploy/server/bootstrap.py
USER 1000:1000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--timeout", "60", "--access-logfile", "-", "cloud_soc.portal.app:create_app()"]
