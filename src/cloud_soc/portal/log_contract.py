"""Pure intake-log projections and validation; no Elasticsearch I/O or HTTP routes."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import re
from cloud_soc.portal.privacy import display, sensitive

from cloud_soc.portal.agent_status import iso, parse_time

CONTRACT_VERSION = 1
INDICES = ("soc-host-raw-*", "soc-network-*", "soc-cloud-aws-*", "soc-cloud-oci-*")
DEFAULT_PAGE_SIZE = 25
PAGE_SIZES = (10, 25, 50)
MAX_WINDOW = timedelta(days=30)
SEARCH_TIMEOUT = "4s"
MAX_RESPONSE_BYTES = 256 * 1024
MAX_DETAIL_BYTES = 64 * 1024
MAX_CURSOR_LENGTH = 8192
TIME_FIELDS = {"ingested": "event.ingested", "event": "@timestamp"}
HOST_SOURCES = {"windows_event", "windows_file", "linux_file", "linux_journald"}
SOURCE_FIELDS = (
    "@timestamp", "event.ingested", "organization.id", "agent.id", "agent.type",
    "host.name", "host.ip", "host.os.type", "host.os.name", "labels.log_source",
    "labels.sensor_platform", "winlog.channel", "log.file.path", "event.dataset",
    "event.code", "event.action", "event.outcome", "user.name", "source.ip",
    "destination.ip", "network.transport", "network.protocol", "flow.final",
    "cloud.provider", "cloud.account.id", "cloud.region", "cloud.service.name", "user.id",
)


@dataclass(frozen=True)
class LogFilters:
    start: str
    end: str
    time_basis: str = "ingested"
    page_size: int = DEFAULT_PAGE_SIZE
    host: str | None = None
    os: str | None = None
    collector: str | None = None
    ip: str | None = None

    @property
    def time_field(self):
        return TIME_FIELDS[self.time_basis]


def parse_filters(pairs, *, now=None):
    """Accept request.args.items(multi=True), rejecting duplicates before any I/O."""
    allowed = {"start", "end", "time_basis", "page_size", "host", "os", "collector", "ip"}
    values = {}
    for key, value in pairs:
        if key not in allowed or key in values:
            raise ValueError("Unsupported or repeated log filter")
        if not isinstance(value, str) or not value or len(value) > 512 or any(ord(c) < 32 for c in value):
            raise ValueError("Invalid log filter value")
        if sensitive(value):
            raise ValueError("Sensitive filter values are not accepted")
        values[key] = value
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("An aware reference time is required")
    if ("start" in values) != ("end" in values):
        raise ValueError("Both start and end are required")
    start = parse_time(values["start"]) if "start" in values else now - timedelta(hours=1)
    end = parse_time(values["end"]) if "end" in values else now
    if start is None or end is None or not timedelta(0) < end - start <= MAX_WINDOW:
        raise ValueError("Use aware timestamps and a positive window of at most 30 days")
    basis = values.get("time_basis", "ingested")
    if basis not in TIME_FIELDS:
        raise ValueError("Unsupported time basis")
    size = values.get("page_size", str(DEFAULT_PAGE_SIZE))
    if size not in {str(number) for number in PAGE_SIZES}:
        raise ValueError("Unsupported page size")
    os_type = values.get("os")
    if os_type not in (None, "windows", "linux", "cloud", "unknown"):
        raise ValueError("Unsupported operating system")
    collector = values.get("collector")
    if collector not in (None, "filebeat", "packetbeat", "cloudtrail", "oci-audit"):
        raise ValueError("Unsupported collector")
    host = values.get("host")
    if host is not None and (len(host) > 253 or host != host.strip()):
        raise ValueError("Invalid host name")
    address = values.get("ip")
    if address is not None:
        try:
            if "%" in address:
                raise ValueError()
            address = str(ipaddress.ip_address(address))
        except ValueError:
            raise ValueError("Use a single IPv4 or IPv6 address, not a subnet") from None
    return LogFilters(iso(start), iso(end), basis, int(size), host, os_type, collector, address)


def document_reference(index, identifier):
    """Validate intake-shaped references; the caller must also reject ES aliases."""
    if (not isinstance(index, str) or len(index.encode("utf-8")) > 255
            or not re.fullmatch(r"soc-(?:host-raw|network|cloud-aws|cloud-oci)-[a-z0-9][a-z0-9_.-]*", index)):
        raise ValueError("Invalid intake index reference")
    if (not isinstance(identifier, str) or not identifier or len(identifier.encode("utf-8")) > 512
            or any(ord(c) < 32 for c in identifier) or sensitive(identifier)):
        raise ValueError("Invalid document reference")
    return {"index": index, "id": identifier}


def field(source, path):
    for name in path.split("."):
        if not isinstance(source, dict):
            return None
        source = source.get(name)
    return source


def operating_system(source):
    if field(source, "labels.log_source") == "aws_cloudtrail" and field(source, "cloud.provider") == "aws":
        return "cloud", "cloud.provider"
    if field(source, "labels.log_source") == "oci_audit" and field(source, "cloud.provider") == "oci":
        return "cloud", "cloud.provider"
    # Network intake deliberately omits host.os.type. Use its explicit sensor tag.
    value = field(source, "host.os.type")
    if value in ("windows", "linux"):
        return value, "host.os.type"
    value = field(source, "labels.sensor_platform")
    if value in ("windows", "linux"):
        return value, "labels.sensor_platform"
    value = field(source, "labels.log_source")
    if value in ("windows_event", "windows_file"):
        return "windows", "labels.log_source"
    if value in ("linux_file", "linux_journald"):
        return "linux", "labels.log_source"
    return "unknown", None


def project_hit(hit):
    """Project metadata only. Free text/raw payloads require a separate access policy."""
    reference = document_reference(hit.get("_index"), hit.get("_id"))
    source = hit.get("_source")
    if not isinstance(source, dict):
        raise ValueError("Missing document source")
    invalid, truncated = [], []

    def string(path):
        value = field(source, path)
        if value is None:
            return None
        if not isinstance(value, str) or not value:
            invalid.append(path)
            return None
        if len(value) > 512:
            truncated.append(path)
        return display(value)

    def timestamp(path):
        value = field(source, path)
        parsed = parse_time(value)
        if value is not None and parsed is None:
            invalid.append(path)
        return iso(parsed) if parsed is not None else None

    def addresses(path, *, many=False):
        value = field(source, path)
        if value is None:
            return [] if many else None
        items = value if many and isinstance(value, list) else [value]
        if len(items) > 16:
            truncated.append(path)
        result = []
        for item in items[:16]:
            try:
                if not isinstance(item, str) or "%" in item:
                    raise ValueError()
                address = str(ipaddress.ip_address(item))
                if address not in result:
                    result.append(address)
            except ValueError:
                invalid.append(path)
        return result if many else (result[0] if result else None)

    source_name = string("labels.log_source")
    stream = "host" if reference["index"].startswith("soc-host-raw-") else "cloud" if reference["index"].startswith(("soc-cloud-aws-", "soc-cloud-oci-")) else "network"
    supported = HOST_SOURCES if stream == "host" else {"oci_audit" if reference["index"].startswith("soc-cloud-oci-") else "aws_cloudtrail"} if stream == "cloud" else {"network_packetbeat"}
    kind = source_name if source_name in supported else "unknown"
    os_type, os_basis = operating_system(source)
    outcome = string("event.outcome")
    if outcome not in (None, "success", "failure", "unknown"):
        invalid.append("event.outcome")
        outcome = None
    final = field(source, "flow.final")
    if final is not None and type(final) is not bool:
        invalid.append("flow.final")
        final = None
    row = {
        "reference": reference, "stream": stream, "source_kind": kind,
        "source_label": source_name, "received_at": timestamp("event.ingested"),
        "event_at": timestamp("@timestamp"), "organization": string("organization.id"),
        "agent_id": string("agent.id"), "collector": string("agent.type"),
        "host_name": string("host.name"), "host_ips": addresses("host.ip", many=True),
        "os": os_type, "os_basis": os_basis, "os_name": string("host.os.name"),
        "channel": string("winlog.channel"), "file_path": string("log.file.path"),
        "dataset": string("event.dataset"), "event_code": string("event.code"),
        "action": string("event.action"), "outcome": outcome or "unknown",
        "user": string("user.name"), "source_ip": addresses("source.ip"),
        "destination_ip": addresses("destination.ip"),
        "transport": string("network.transport"), "protocol": string("network.protocol"),
        "flow_final": final, "parse_status": "not_evaluated",
        "cloud_provider": string("cloud.provider"), "cloud_account": string("cloud.account.id"), "cloud_region": string("cloud.region"),
        "cloud_service": string("cloud.service.name"), "actor_id": string("user.id"),
    }
    row["quality"] = {"invalid_fields": sorted(set(invalid)), "truncated_fields": sorted(set(truncated))}
    return row
