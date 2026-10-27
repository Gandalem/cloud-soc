"""Fixed diagnostic codes for workers; never expose server bodies or input text."""
import sqlite3

from elasticsearch import ApiError, ConnectionError, ConnectionTimeout


REASONS = frozenset({
    'partial_search', 'index_alias_not_allowed', 'unexpected_index',
    'receipt_mapping_missing', 'cursor_not_advancing', 'window_page_limit',
    'partial_bulk_response', 'normalization_bulk_failed', 'scan_scope_changed',
    'active_state_limit', 'input_spool_limit', 'input_document_size_limit',
    'partial_input_scan', 'input_cursor_or_page_invalid', 'input_page_limit',
    'input_scan_scope_changed', 'normalization_time_mapping_required',
    'legacy_missing_normalization_time_requires_explicit_exclusion',
    'unexpected_normalized_index', 'incomplete_evidence', 'outside_receipt_range',
    'invalid_reference', 'legacy_scope_check_failed', 'clock_regression',
    'rule_or_scope_changed_requires_new_state', 'unsafe_state_path',
    'state_file_must_be_private_and_regular',
})


class WorkerFailure(RuntimeError):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def error_code(error, fallback='processing_failed'):
    if isinstance(error, WorkerFailure):
        return error.code
    if isinstance(error, sqlite3.Error):
        code = getattr(error, 'sqlite_errorcode', None)
        if code is not None and code & 255 in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
            return 'checkpoint_locked'
        return 'checkpoint_storage_failed'
    if isinstance(error, ConnectionTimeout):
        return 'elasticsearch_timeout'
    if isinstance(error, ConnectionError):
        return 'elasticsearch_connection_failed'
    if isinstance(error, ApiError):
        return {401: 'authentication_failed_or_key_expired', 403: 'authorization_denied',
                404: 'elasticsearch_resource_missing', 429: 'elasticsearch_overloaded',
                400: 'elasticsearch_request_rejected', 503: 'elasticsearch_unavailable'}.get(
                    error.status_code, 'elasticsearch_request_failed')
    if isinstance(error, RecursionError):
        return 'input_nesting_limit'
    if isinstance(error, (ValueError, RuntimeError)) and error.args and isinstance(error.args[0], str) and error.args[0] in REASONS:
        return error.args[0]
    return fallback
