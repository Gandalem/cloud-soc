#!/bin/sh
# This fixed command never exposes a shell or reads Apache originals for the client.
set -eu
if [ "${SSH_ORIGINAL_COMMAND-}" != cloud-soc-web-export ]; then
    printf '%s\n' 'Web export command refused.' >&2
    exit 1
fi
exec /usr/bin/sudo -n /usr/bin/python3 -I /opt/cloud-soc-web/deploy/web/aws-entry.py --config /etc/cloud-soc-web/producer.json --export
