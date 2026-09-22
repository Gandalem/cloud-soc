"""Bounded, read-only intake queries. Cursor contents never grant ES authority."""

import base64
from dataclasses import asdict
import hmac
import json
import time

from elasticsearch import NotFoundError
from cloud_soc.portal.security_detail import DETAIL_FIELDS, security_detail

from cloud_soc.portal.log_contract import (
    CONTRACT_VERSION, INDICES, MAX_CURSOR_LENGTH, MAX_DETAIL_BYTES, MAX_RESPONSE_BYTES,
    SEARCH_TIMEOUT, SOURCE_FIELDS, document_reference, parse_filters, project_hit,
)

PIT_TTL = "90s"
CURSOR_SECONDS = 600

# Source-based runtime fields avoid keyword/text mapping differences without
# changing stored mappings. These scripts are fixed, never provided by callers.
FIELD_HELPER = """
def value(def s, String path) {
  for (def part : path.splitOnToken('.')) {
    if (!(s instanceof Map)) return null;
    s = s.get(part);
  }
  return s;
}
"""
OS_SCRIPT = FIELD_HELPER + """
def s = params._source;
if (value(s, 'labels.log_source') == 'aws_cloudtrail' && value(s, 'cloud.provider') == 'aws') { emit('cloud'); return; }
if (value(s, 'labels.log_source') == 'oci_audit' && value(s, 'cloud.provider') == 'oci') { emit('cloud'); return; }
def os = value(s, 'host.os.type');
if (os == 'windows' || os == 'linux') { emit(os); return; }
os = value(s, 'labels.sensor_platform');
if (os == 'windows' || os == 'linux') { emit(os); return; }
def label = value(s, 'labels.log_source');
if (label == 'windows_event' || label == 'windows_file') emit('windows');
else if (label == 'linux_file' || label == 'linux_journald') emit('linux');
else emit('unknown');
"""
IP_SCRIPT = FIELD_HELPER + """
for (def path : ['host.ip', 'source.ip', 'destination.ip']) {
  def v = value(params._source, path);
  if (v instanceof String) emit(v);
  else if (path == 'host.ip' && v instanceof List) {
    for (def address : v) { if (address instanceof String) emit(address); }
  }
}
"""


class LogQueryError(Exception):
    def __init__(self, code, status, message):
        super().__init__(message)
        self.code, self.status = code, status


def invalid():
    return LogQueryError("invalid_log_query", 400, "조회 조건이나 페이지 정보가 올바르지 않습니다. 처음부터 다시 조회하세요.")


def expired():
    return LogQueryError("cursor_expired", 410, "조회 스냅샷이 만료되었습니다. 새로고침으로 첫 페이지부터 조회하세요.")


def unavailable():
    return LogQueryError("logs_unavailable", 503, "로그를 조회하지 못했습니다. 서버 연결·조회 권한·필드 매핑을 확인하세요.")


def bounded_json(value, limit=MAX_RESPONSE_BYTES):
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > limit:
        raise LogQueryError("response_too_large", 413, "조회 결과가 표시 한도를 초과했습니다. 페이지 크기나 조회 범위를 줄이세요.")
    return encoded


def pack(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def unpack(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def filters_from_dict(value):
    if not isinstance(value, dict):
        raise ValueError()
    return parse_filters([(key, str(item)) for key, item in value.items() if item is not None])


def valid_sort(value):
    return (isinstance(value, list) and len(value) == 2
            and all(type(item) is int and -(2**63) <= item < 2**63 for item in value)
            and value[1] >= 0)


class LogReader:
    def __init__(self, client, *, secret, principal, clock=time.time):
        self.client = client.options(request_timeout=5, max_retries=0) if client is not None else None
        self.key = hmac.digest(secret.encode(), b"cloud-soc-log-cursor-v1", "sha256")
        self.principal, self.clock = principal, clock

    def encode(self, state):
        payload = pack(bounded_json(state))
        result = payload + "." + pack(hmac.digest(self.key, payload.encode(), "sha256"))
        if len(result) > MAX_CURSOR_LENGTH:
            raise unavailable()
        return result

    def decode(self, token):
        try:
            if not isinstance(token, str) or not token or len(token) > MAX_CURSOR_LENGTH:
                raise ValueError()
            payload, signature = token.split(".")
            if not hmac.compare_digest(unpack(signature), hmac.digest(self.key, payload.encode("ascii"), "sha256")):
                raise ValueError()
            state = json.loads(unpack(payload))
            if (set(state) != {"v", "principal", "pit", "filters", "after", "expires"}
                    or state["v"] != CONTRACT_VERSION or state["principal"] != self.principal
                    or not isinstance(state["pit"], str) or not state["pit"]
                    or not valid_sort(state["after"]) or type(state["expires"]) is not int):
                raise ValueError()
            parsed = filters_from_dict(state["filters"])
            if asdict(parsed) != state["filters"]:
                raise ValueError()
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise invalid() from None
        if state["expires"] <= self.clock():
            raise expired()
        return state, parsed

    def require_client(self):
        if self.client is None:
            raise LogQueryError("monitor_not_configured", 503, "로그 조회 계정이 준비되지 않았습니다. 중앙 서버 업데이트 절차를 확인하세요.")

    def close(self, pit):
        if pit:
            try:
                self.client.close_point_in_time(id=pit)
            except Exception:
                # Bounded idle TTL still releases the snapshot; never log its ID.
                pass

    def indices(self, name):
        resolved = self.client.indices.resolve_index(name=name, expand_wildcards="open",
                                                     allow_no_indices=True, ignore_unavailable=True)
        names = [entry["name"] for entry in resolved["indices"]]
        for index in names:
            document_reference(index, "validation")
        # Alias/data-stream matches are not a substitute for a concrete intake index.
        if resolved.get("aliases") or resolved.get("data_streams"):
            raise unavailable()
        return names

    def body(self, filters, pit, after):
        clauses = [{"range": {filters.time_field: {"gte": filters.start, "lt": filters.end}}}]
        runtime = {}
        for value, path in ((filters.host, "host.name"), (filters.collector, "agent.type")):
            if value is not None:
                clauses.append({"term": {path: value}})
        if filters.os is not None:
            runtime["soc_query_os"] = {"type": "keyword", "script": {"source": OS_SCRIPT}}
            clauses.append({"term": {"soc_query_os": filters.os}})
        if filters.ip is not None:
            runtime["soc_query_ip"] = {"type": "ip", "script": {"source": IP_SCRIPT}}
            clauses.append({"term": {"soc_query_ip": filters.ip}})
        body = {
            "pit": {"id": pit, "keep_alive": PIT_TTL}, "size": filters.page_size + 1,
            "track_total_hits": False, "timeout": SEARCH_TIMEOUT, "_source": list(SOURCE_FIELDS),
            "query": {"bool": {"filter": clauses}},
            "sort": [{filters.time_field: {"order": "desc", "unmapped_type": "date", "numeric_type": "date"}},
                     {"_shard_doc": "asc"}],
        }
        if runtime:
            body["runtime_mappings"] = runtime
        if after is not None:
            body["search_after"] = after
        return body

    def check_mappings(self, indices, filters):
        fields = [filters.time_field, "host.name", "agent.type"]
        caps = self.client.field_caps(index=indices, fields=fields, include_unmapped=True)["fields"]
        required = {filters.time_field: {"date", "date_nanos"}}
        if filters.host is not None:
            required["host.name"] = {"keyword"}
        if filters.collector is not None:
            required["agent.type"] = {"keyword"}
        for name, allowed in required.items():
            for kind, info in caps.get(name, {}).items():
                if kind == "unmapped":
                    continue
                if kind not in allowed or not info.get("searchable") or (name == filters.time_field and not info.get("aggregatable")):
                    raise unavailable()

    def page(self, pairs):
        pairs = list(pairs)
        tokens = [value for key, value in pairs if key == "cursor"]
        pit, after, state = None, None, None
        try:
            if tokens:
                if len(pairs) != 1:
                    raise invalid()
                state, filters = self.decode(tokens[0])
                pit, after = state["pit"], state["after"]
            else:
                filters = parse_filters(pairs)
        except ValueError:
            raise invalid() from None
        self.require_client()
        try:
            if state is None:
                names = self.indices(INDICES)
                if not names:
                    return bounded_json(self.result(filters, [], None))
                self.check_mappings(names, filters)
                opened = self.client.open_point_in_time(index=names, keep_alive=PIT_TTL,
                                                        allow_partial_search_results=False)
                pit = opened["id"]
                if opened.get("_shards", {}).get("failed", 0):
                    raise unavailable()
                state = {"v": CONTRACT_VERSION, "principal": self.principal, "pit": pit,
                         "filters": asdict(filters), "after": None, "expires": int(self.clock()) + CURSOR_SECONDS}
            response = self.client.search(body=self.body(filters, pit, after), allow_partial_search_results=False)
            pit = response.get("pit_id", pit)
            if response.get("timed_out") or response.get("terminated_early") or response.get("_shards", {}).get("failed", 0):
                raise unavailable()
            hits = response["hits"]["hits"]
            if len(hits) > filters.page_size + 1:
                raise unavailable()
            last = (-after[0], after[1]) if after else None
            identities = set()
            for hit in hits:
                order = hit.get("sort")
                if not valid_sort(order):
                    raise unavailable()
                order = (-order[0], order[1])
                identity = (hit["_index"], hit["_id"])
                if (last is not None and order <= last) or identity in identities:
                    raise unavailable()
                last = order
                identities.add(identity)
            rows = [project_hit(hit) for hit in hits[:filters.page_size]]
            token = None
            if len(hits) > filters.page_size:
                token = self.encode({**state, "pit": pit, "after": hits[filters.page_size - 1]["sort"]})
            encoded = bounded_json(self.result(filters, rows, token))
            if token is None:
                self.close(pit)
            return encoded
        except NotFoundError:
            self.close(pit)
            raise expired() from None
        except Exception as error:
            self.close(pit)
            if isinstance(error, LogQueryError):
                raise
            raise unavailable() from None

    @staticmethod
    def result(filters, rows, token):
        return {"contract_version": CONTRACT_VERSION, "filters": asdict(filters), "rows": rows,
                "next_cursor": token, "raw_access": "restricted", "total": None,
                "snapshot_idle_seconds": 90}

    def detail(self, pairs):
        pairs = list(pairs)
        try:
            if len(pairs) != 2 or {key for key, _ in pairs} != {"index", "id"}:
                raise ValueError()
            reference = document_reference(**{"index": dict(pairs)["index"], "identifier": dict(pairs)["id"]})
        except (ValueError, UnicodeError):
            raise invalid() from None
        self.require_client()
        try:
            if self.indices(reference["index"]) != [reference["index"]]:
                raise LogQueryError("log_not_found", 404, "문서를 찾을 수 없습니다. 삭제되었거나 보존 기간이 지났을 수 있습니다.")
            hit = self.client.get(index=reference["index"], id=reference["id"],
                                  source_includes=list(SOURCE_FIELDS) + list(DETAIL_FIELDS))
            if hit["_index"] != reference["index"] or hit["_id"] != reference["id"]:
                raise unavailable()
            return bounded_json({"contract_version": CONTRACT_VERSION, "row": project_hit(hit),
                                 "security": security_detail(hit.get("_source")),
                                 "raw_access": "restricted"}, MAX_DETAIL_BYTES)
        except NotFoundError:
            raise LogQueryError("log_not_found", 404, "문서를 찾을 수 없습니다. 삭제되었거나 보존 기간이 지났을 수 있습니다.") from None
        except Exception as error:
            if isinstance(error, LogQueryError):
                raise
            raise unavailable() from None
