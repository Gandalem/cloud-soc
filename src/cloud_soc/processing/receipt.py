"""Read complete millisecond buckets, then enforce exact source-time bounds.

Elasticsearch date fields index milliseconds while _source can retain microseconds.
The widened query is only a candidate scan; it must never extend checkpoint coverage.
"""
from datetime import timedelta
from cloud_soc.portal.agent_status import parse_time, iso


def bounds(lower, end):
    start_time, end_time = parse_time(lower), parse_time(end)
    if start_time is None or end_time is None or end_time < start_time:
        raise ValueError('outside_receipt_range')
    floor = start_time.replace(microsecond=(start_time.microsecond // 1000) * 1000)
    ceiling = end_time.replace(microsecond=(end_time.microsecond // 1000) * 1000)
    if ceiling < end_time:
        ceiling += timedelta(milliseconds=1)
    return start_time, end_time, floor, ceiling


def query(field, lower, end):
    _, _, floor, ceiling = bounds(lower, end)
    return {'range': {field: {'gte': iso(floor), 'lt': iso(ceiling)}}}


def contains(value, lower, end):
    stamp = parse_time(value)
    start_time, end_time, floor, ceiling = bounds(lower, end)
    if stamp is None or not floor <= stamp < ceiling:
        # Outside the requested candidate buckets is still a protocol failure.
        raise ValueError('outside_receipt_range')
    return start_time <= stamp < end_time
