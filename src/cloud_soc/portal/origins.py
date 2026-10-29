"""Exact HTTPS origins shared by deployment and Portal, without network access."""
import ipaddress
import re
from urllib.parse import urlsplit


def https_origin(value):
    if not isinstance(value, str) or len(value) > 280 or not re.fullmatch(
            r'https://[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?', value):
        raise ValueError('HTTPS 주소만 입력하세요. 계정·경로·쿼리는 사용할 수 없습니다.')
    parsed = urlsplit(value)
    try:
        port = parsed.port
        host = parsed.hostname
        if port == 0 or len(host) > 253:
            raise ValueError
        if all(c in '0123456789.' for c in host):
            address = ipaddress.IPv4Address(host)
            if address.is_unspecified or address.is_multicast:
                raise ValueError
        elif any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                 for label in host.split('.')):
            raise ValueError
    except ValueError:
        raise ValueError('접속할 DNS 이름·IPv4·포트 형식을 확인하세요.') from None
    return 'https://' + host + (':' + str(port) if port not in (None, 443) else '')


def additional_origins(values):
    if not isinstance(values, list) or len(values) > 16:
        raise ValueError('접속 주소 목록의 형식과 개수 제한을 확인하세요.')
    return list(dict.fromkeys(https_origin(value) for value in values))
