# Pipeline availability watchdog

This additive host timer checks the existing central pipeline every minute. It does not
change detection rules, ES documents, agent keys, checkpoints, or the running Portal.
It uses the current immutable runtime image and two installed, root-owned scripts.

## Default policy

| Signal | Trigger | Recovery |
| --- | --- | --- |
| Root/data filesystem usage | warning at 75%, critical at 85% | below 70% |
| Last intake receipt | absent for 5 minutes, absent in the last day, or invalid future time | fresh receipt |
| Five-minute intake volume | zero, or below 20% of the preceding 30-minute five-minute average when that average is at least 100 | threshold satisfied |
| General/priority normalizer | failed/missing/unknown state, checkpoint older than 5 minutes, or invalid future checkpoint | success/running with fresh checkpoint |
| Intake/checkpoint read | unavailable, partial shards, unexpected index scope | successful complete read |

Each fault and recovery needs two consecutive observations; a warning escalating to
critical also sends a transition. Identical active conditions do not repeat every
minute. The one-minute timer starts its next interval after the bounded probe exits,
so detection is not an exact wall-clock deadline. Missing metrics never imply recovery.
Counts are aggregate intake, not proof that every expected host or organization is
reporting. Quiet individual sources need an explicit expected-source inventory later.

## Install on the approved central host

Use an exact reviewed release checkout. First inspect the plan, then install:

```sh
sudo python3 deploy/server/install-health-watchdog.py --workspace "$PWD" --state /home/ubuntu/cloud-soc/state/server
sudo python3 deploy/server/install-health-watchdog.py --workspace "$PWD" --state /home/ubuntu/cloud-soc/state/server --apply
```

The installer discovers the existing Portal mounts/network/image and refuses to enable
the timer until metrics and the existing enabled Slack destination can be read. It
does not restart SOC containers or create permissions, keys, destinations or volumes.
The separate probe has read-only mounts for CA and monitor password; only `/health`
is writable. The host reads the existing enabled Slack configuration with a read-only
SQLite query and passes the encrypted destination/key through container stdin only.
This avoids SQLite WAL coordination errors on a read-only notification-directory mount;
the probe cannot modify notification settings and no secret is passed in argv or logs.
The probe runs as the existing monitor password
and notification directory owner (UID 1000 on the central host), with all capabilities
dropped. Its public script is mounted read-only; the host runner and configuration
remain root-only, and only the separate data subdirectory is owned by the probe user.
It never mounts the Docker socket or the host filesystem. It sends directly to the
existing destination, independently of the security-alert scanner and ES availability. No raw events, host
identities, webhook URL or credentials are included in its messages/journal.

```sh
sudo systemctl start cloud-soc-health-watchdog.service
sudo systemctl status cloud-soc-health-watchdog.timer --no-pager
sudo journalctl -u cloud-soc-health-watchdog.service -n 8 --no-pager
sudo python3 /home/ubuntu/cloud-soc/state/server/health-watchdog/host.py --config /home/ubuntu/cloud-soc/state/server/health-watchdog/config.json --dry-run
```

An explicitly labelled installation message verifies actual Slack acceptance:

```sh
sudo python3 /home/ubuntu/cloud-soc/state/server/health-watchdog/host.py --config /home/ubuntu/cloud-soc/state/server/health-watchdog/config.json --test-notification
```

One queued message is sent per cycle. Definite connection/rate-limit failures retry,
respecting Retry-After; repeated failures become permanent after eight attempts. A
crash/ambiguous POST is held as `unknown` rather than duplicated automatically. Disabled
or unreadable Slack settings yield `blocked` and are retried after configuration is
restored. Inspect the monitor's private state/journal for these delivery states; absence
of a Slack message does not establish successful delivery. The monitor's own expendable
16MiB reserve is released at 85% disk use to leave room for durable state; it does not
delete evidence or change ES disk watermarks.

## Changes and removal

The installed private config pins the runtime image and has an optional `policy` object;
the script validates thresholds before use. Review it after runtime/schema changes,
then rerun the installer to adopt the current image. Stop the timer before any manual
state repair. Preserve `state.json` to preserve deduplication and delivery audit.

```sh
sudo systemctl disable --now cloud-soc-health-watchdog.timer
```

This disables future monitoring without touching SOC services or monitor history.
This is an on-host watchdog: EC2 shutdown, Docker daemon failure, host network loss,
or a completely unwritable filesystem can prevent it from running/sending. Independent
off-host heartbeat monitoring is a separate layer; this implementation does not claim
to detect total host loss. End-to-end local tests mock the sender and never send Slack.
Actual operation and a real installation notification must be verified separately.
