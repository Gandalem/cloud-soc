#!/usr/bin/env bash
# Dedicated NEW Amazon Linux 2023 app host. No AWS identity/SG/ALB changes.
set -euo pipefail
if [[ ${1:-} != --apply || $# != 1 ]]; then
  printf '%s\n' 'Plan: install pinned Security Mall + private-state HMAC audit + Nginx metadata + CloudWatch file configuration.' 'Run only on the approved NEW Amazon Linux 2023 instance: sudo bash bootstrap-al2023.sh --apply'
  exit 0
fi
[[ $EUID == 0 ]] || { echo 'Run with sudo on the new app instance.' >&2; exit 1; }
source /etc/os-release
[[ $ID == amzn && $VERSION_ID == 2023 ]] || { echo 'Amazon Linux 2023 required.' >&2; exit 1; }
[[ ! -e /opt/security-mall && ! -e /var/lib/security-mall ]] || { echo 'Existing app/state found; preserve it and stop.' >&2; exit 1; }
umask 027
dnf install -y java-17-amazon-corretto-devel git nginx amazon-cloudwatch-agent
id security-mall >/dev/null 2>&1 || useradd --system --home-dir /var/lib/security-mall --shell /sbin/nologin security-mall
install -d -o root -g security-mall -m 0750 /opt/security-mall
install -d -o security-mall -g security-mall -m 0700 /var/lib/security-mall /var/lib/security-mall/data /var/lib/security-mall/audit /var/cache/security-mall /var/log/security-mall
git clone https://github.com/ZIYA0614/security-mall.git /opt/security-mall/source
git -C /opt/security-mall/source checkout --detach aba2b423157cdcb4562fb0eaab3694e379b900e4
[[ $(git -C /opt/security-mall/source rev-parse HEAD) == aba2b423157cdcb4562fb0eaab3694e379b900e4 ]]
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  'https://raw.githubusercontent.com/Gandalem/cloud-soc/02b9365a10e7bbb137de7e83c3c4cb32a5896342/deploy/security-mall/login-audit/security-mall-login.patch' \
  --output /opt/security-mall/login-audit.patch
printf '%s\n' 'e7a25fe180f69c4502a373de6c90a199b7a0fa01454c950d7b19a8999cd2b68c  /opt/security-mall/login-audit.patch' | sha256sum --check -
git -C /opt/security-mall/source apply --check /opt/security-mall/login-audit.patch
git -C /opt/security-mall/source apply /opt/security-mall/login-audit.patch
chown -R security-mall:security-mall /opt/security-mall/source
runuser -u security-mall -- bash -c 'cd /opt/security-mall/source && GRADLE_USER_HOME=/var/cache/security-mall/gradle GRADLE_OPTS="-Xmx128m" bash gradlew --no-daemon --max-workers=1 -Dorg.gradle.jvmargs="-Xmx384m -XX:MaxMetaspaceSize=256m" bootJar'
mapfile -t jars < <(find /opt/security-mall/source/build/libs -maxdepth 1 -type f -name '*.jar' ! -name '*-plain.jar')
[[ ${#jars[@]} == 1 ]] || { echo 'Expected exactly one boot JAR.' >&2; exit 1; }
install -o root -g root -m 0644 "${jars[0]}" /opt/security-mall/app.jar
cat > /opt/security-mall/application-observability.properties <<'EOF'
server.address=127.0.0.1
server.port=8080
server.forward-headers-strategy=none
spring.datasource.url=jdbc:h2:file:/var/lib/security-mall/data/testdb;DB_CLOSE_ON_EXIT=FALSE
spring.h2.console.enabled=false
logging.file.name=/var/log/security-mall/application.log
logging.level.org.hibernate.SQL=OFF
logging.level.org.hibernate.orm.jdbc.bind=OFF
EOF
cat > /etc/systemd/system/security-mall.service <<'EOF'
[Unit]
Description=Security Mall dedicated lab application
After=network-online.target
Wants=network-online.target
[Service]
User=security-mall
Group=security-mall
WorkingDirectory=/var/lib/security-mall
ExecStart=/usr/bin/java -Xms128m -Xmx768m -Dmall.audit.dir=/var/lib/security-mall/audit -jar /opt/security-mall/app.jar --spring.config.additional-location=file:/opt/security-mall/application-observability.properties
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/security-mall /var/log/security-mall
[Install]
WantedBy=multi-user.target
EOF
cp --preserve /etc/nginx/nginx.conf /etc/nginx/nginx.conf.cloud-soc-before
cat > /etc/nginx/nginx.conf <<'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;
include /usr/share/nginx/modules/*.conf;
events { worker_connections 1024; }
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;
  map $uri $soc_route { default "<other>"; / "/"; /login "/login"; /board "/board"; }
  map $status $soc_error { default 0; ~^[45] 1; }
  log_format soc_mall escape=json '{"schema":"cloud-soc-security-mall-web-v1","timestamp":"$time_iso8601","source_ip":"$remote_addr","method":"$request_method","route":"$soc_route","status":$status,"bytes":$body_bytes_sent,"duration":$request_time}';
  access_log /var/log/nginx/security-mall-access.jsonl soc_mall;
  access_log /var/log/nginx/security-mall-http-errors.jsonl soc_mall if=$soc_error;
  server {
    listen 80;
    server_name _;
    location / {
      proxy_pass http://127.0.0.1:8080;
      proxy_set_header Host $host;
      proxy_set_header X-Request-ID $request_id;
      proxy_set_header X-Forwarded-For "";
      proxy_set_header X-Forwarded-Proto "";
    }
  }
}
EOF
nginx -t
# Agent sends fixed metadata files only. Never collect HMAC key, DB, raw bodies,
# generic Java error/stack text or Nginx error.log containing untrusted URLs.
cat > /opt/aws/amazon-cloudwatch-agent/etc/cloud-soc-security-mall.json <<'EOF'
{
  "agent": {"region": "ap-southeast-2", "run_as_user": "root"},
  "logs": {"logs_collected": {"files": {"collect_list": [
    {"file_path": "/var/log/nginx/security-mall-access.jsonl", "log_group_name": "/cloud-soc/security-mall/access", "log_stream_name": "{instance_id}"},
    {"file_path": "/var/log/nginx/security-mall-http-errors.jsonl", "log_group_name": "/cloud-soc/security-mall/http-errors", "log_stream_name": "{instance_id}"},
    {"file_path": "/var/lib/security-mall/audit/security-audit.jsonl", "log_group_name": "/cloud-soc/security-mall/login-audit", "log_stream_name": "{instance_id}"}
  ]}}}
}
EOF
systemctl daemon-reload
systemctl enable --now security-mall
for _ in {1..90}; do
  if curl --fail --silent http://127.0.0.1:8080/login >/dev/null; then break; fi
  sleep 1
done
systemctl enable --now nginx
for route in / /login /board; do
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1${route}")
  [[ $status == 200 ]] || { echo "Page check failed: $route HTTP $status" >&2; exit 1; }
done
curl --silent --output /dev/null http://127.0.0.1/cloud-soc-missing-page
curl --silent --output /dev/null --data 'username=cloud-soc-synthetic-check&password=not-a-real-credential' http://127.0.0.1/login
[[ -s /var/lib/security-mall/audit/security-audit.jsonl ]] || { echo 'Login audit not observed.' >&2; exit 1; }
TOKEN=$(curl --fail --silent --connect-timeout 2 --max-time 3 --request PUT --header 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token) || { echo 'Web ready; IMDSv2 unavailable. CloudWatch delivery not configured.' >&2; exit 10; }
# IAM info contains profile metadata, not credentials. Never read security-credentials.
curl --fail --silent --connect-timeout 2 --max-time 3 --header "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/info >/dev/null || { echo 'Web ready; attach an approved instance role before CloudWatch startup.' >&2; exit 10; }
unset TOKEN
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a fetch-config -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/cloud-soc-security-mall.json
printf '%s\n' 'Local page/audit checks passed. Verify actual CloudWatch log events separately; agent running is not proof of delivery.'
