# Linux amd64 disposable component lab only; never a production image or host Docker mount.
FROM docker:27.5.1-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce AS engine
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
COPY --from=engine /usr/local/bin/docker /usr/local/bin/dockerd /usr/local/bin/containerd /usr/local/bin/containerd-shim-runc-v2 /usr/local/bin/runc /usr/local/bin/
COPY --from=engine /bin/busybox /fixture/busybox
COPY --from=engine /lib/ld-musl-x86_64.so.1 /fixture/ld-musl-x86_64.so.1
WORKDIR /app
COPY deploy/server /app/deploy/server
COPY tests/manual/server_removal_docker_live.py /app/tests/manual/server_removal_docker_live.py
ENV SOC_SERVER_DISPOSABLE_LAB=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python", "/app/tests/manual/server_removal_docker_live.py"]
