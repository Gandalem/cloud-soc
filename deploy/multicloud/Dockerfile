FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt requirements-multicloud.txt constraints.txt ./
RUN pip install --no-cache-dir -c constraints.txt -r requirements-multicloud.txt
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps . && useradd --uid 10001 --create-home collector && mkdir -p /state && chown collector /state
USER 10001:10001
ENTRYPOINT ["python", "-m", "cloud_soc.multicloud"]
