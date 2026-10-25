"""Optional complete package-DB schema group; importable by stdlib-only backup tools."""

TABLES = {
    'managed_devices': 'id label organization os purpose package_id state version created updated'.split(),
    'device_operations': 'id device_id actor action fingerprint state result created updated'.split(),
    'device_transfers': 'device_id operation_id enrollment_id sealed created'.split(),
    'device_audit': 'seq device_id actor action operation_id at'.split(),
}
