# Dedicated CI image. Production image, UID and permission handling are unchanged.
FROM cloud-soc:ci
USER 0:0
RUN python -m pip install --no-cache-dir -c /app/constraints.txt pytest==9.1.1
COPY tests /app/tests
ENV PYTHONPATH=/app/src:/app/tests
ENTRYPOINT ["python", "/app/tests/linux_deployment_ownership.py"]
