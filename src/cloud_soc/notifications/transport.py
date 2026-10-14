"""Slack-only HTTPS with DNS pinning, TLS verification and no proxy/redirects."""
from dataclasses import dataclass
import http.client
import ipaddress
import json
import re
import socket
import ssl

HOST = 'hooks.slack.com'
PATTERN = re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{6,63}/[A-Z0-9]{7,64}/[A-Za-z0-9_-]{16,256}')


class SlackError(ValueError):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status


def validate_url(value):
    if not isinstance(value, str) or not PATTERN.fullmatch(value):
        raise SlackError('invalid_slack_webhook')
    return value


def addresses(resolver=None):
    try:
        rows = (resolver or socket.getaddrinfo)(HOST, 443, type=socket.SOCK_STREAM)
        if not rows or len(rows) > 32:
            raise ValueError()
        for family, kind, protocol, _, address in rows:
            ip = ipaddress.ip_address(address[0])
            if family not in (socket.AF_INET, socket.AF_INET6) or not ip.is_global or ip.is_multicast or ip.is_reserved:
                raise ValueError()
        return rows
    except Exception:
        raise SlackError('slack_address_unavailable', 503) from None


@dataclass(frozen=True)
class Result:
    outcome: str
    code: str
    retry_after: int = 0


class PinnedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        # Connect to the numeric address we validated. SNI/certificate checks still use Slack's hostname.
        rows = addresses()
        last = None
        for family, kind, protocol, _, address in rows:
            raw = socket.socket(family, kind, protocol)
            raw.settimeout(self.timeout)
            try:
                raw.connect(address)
                self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
                return
            except Exception:
                raw.close();last = True
        if last:
            raise SlackError('slack_connection_failed', 503)


def send(url, payload):
    validate_url(url)
    body = json.dumps(payload, ensure_ascii=True).encode()
    if len(body) > 12000:
        return Result('permanent', 'message_too_large')
    conn = PinnedHTTPS(HOST, timeout=5, context=ssl.create_default_context())
    writing = False
    try:
        conn.connect()
        writing = True
        conn.request('POST', url[len('https://' + HOST):], body=body,
                     headers={'Content-Type': 'application/json', 'User-Agent': 'Cloud-SOC-Notifications/1'})
        response = conn.getresponse()
        reply = response.read(65)
        if response.status == 200 and reply.strip() == b'ok':
            return Result('sent', 'slack_accepted')
        if response.status == 429:
            delay = response.getheader('Retry-After', '')
            # Never shorten a valid server-specified delay. Excessive delays become visible holds.
            if not re.fullmatch(r'[0-9]{1,7}', delay) or int(delay) > 86400:
                return Result('permanent', 'rate_limit_requires_review')
            return Result('retry', 'slack_rate_limited', max(1, int(delay)))
        if 500 <= response.status <= 599 or response.status == 408:
            return Result('retry', 'slack_temporarily_unavailable', 30)
        # Includes redirects: neither the Location header nor response body is followed/exposed.
        return Result('permanent', 'slack_rejected')
    except Exception:
        # Incoming webhooks have no idempotency key. Do not silently duplicate an ambiguous POST.
        return Result('unknown' if writing else 'retry', 'delivery_unconfirmed' if writing else 'slack_connection_failed', 30)
    finally:
        conn.close()
