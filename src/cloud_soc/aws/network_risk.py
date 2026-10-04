"""Assess selected ingress metadata only. Missing/unsupported requests stay unknown."""
from ipaddress import ip_network


def public_management_ingress(request):
    if not isinstance(request, dict):
        return None
    permissions = request.get('ipPermissions')
    permissions = permissions.get('items') if isinstance(permissions, dict) else permissions
    if not isinstance(permissions, list) or not permissions or len(permissions) > 100:
        return None
    unknown = False
    for permission in permissions:
        if not isinstance(permission, dict):
            unknown = True
            continue
        protocol = permission.get('ipProtocol')
        low, high = permission.get('fromPort'), permission.get('toPort')
        if protocol in ('-1', -1):
            management = True
        elif protocol in ('tcp', '6', 6) and type(low) is int and type(high) is int and 0 <= low <= high <= 65535:
            management = any(low <= port <= high for port in (22, 3389))
        elif protocol in ('udp', '17', 17, 'icmp', '1', 1, 'icmpv6', '58', 58):
            management = False
        else:
            unknown = True
            continue
        if not management:
            continue
        for key, cidr_key in (('ipRanges', 'cidrIp'), ('ipv6Ranges', 'cidrIpv6')):
            rows = permission.get(key, [])
            rows = rows.get('items') if isinstance(rows, dict) else rows
            if not isinstance(rows, list) or len(rows) > 100:
                unknown = True
                continue
            for row in rows:
                try:
                    cidr = row.get(cidr_key) if isinstance(row, dict) else None
                    if not isinstance(cidr, str):
                        raise ValueError()
                    network = ip_network(cidr, strict=False)
                    if network.prefixlen == 0:
                        return True
                except ValueError:
                    unknown = True
    return None if unknown else False
