"""Explicit no-overwrite migration. Source retained until operator cutover/rotation.

No settings, running containers, key privileges, or checkpoints are changed.
"""
import argparse
import hmac
import json
import os
from pathlib import Path
import sys
from cloud_soc.secret_store import SecretError,private_bytes,configuration,KMS,encrypt,decrypt

def migrate(source,destination,context,backend,*,apply=False):
    source,destination=Path(source),Path(destination)
    if not source.is_absolute() or not destination.is_absolute() or source==destination:raise SecretError('migration_paths_invalid')
    if destination.exists() or destination.is_symlink():raise SecretError('migration_destination_exists')
    if any(p.is_symlink() for p in (destination.parent,*destination.parents)):raise SecretError('migration_path_unsafe')
    if not destination.parent.is_dir() or destination.parent.stat().st_mode & 0o077:raise SecretError('migration_directory_not_private')
    info=source.stat();raw=private_bytes(source,16384)
    try:value=raw.decode().strip()
    except UnicodeError:raise SecretError('migration_input_invalid') from None
    if not value or raw.lstrip().startswith(b'{'):raise SecretError('migration_plaintext_required')
    if not apply:return {'plan_valid':True,'writes':False,'source_retained':True,'backend_contacted':False}
    sealed=encrypt(value,context,backend)
    if not hmac.compare_digest(decrypt(sealed,context,backend).encode(),value.encode()):raise SecretError('migration_verification_failed')
    # Recheck input bytes/identity before writing the verified ciphertext.
    fresh=source.stat()
    if (fresh.st_ino,fresh.st_dev,fresh.st_mtime_ns)!=(info.st_ino,info.st_dev,info.st_mtime_ns) or private_bytes(source,16384)!=raw:raise SecretError('migration_source_changed')
    payload=json.dumps(sealed,sort_keys=True).encode()+b'\n'
    descriptor=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as out:
        if os.geteuid()==0:os.fchown(out.fileno(),info.st_uid,info.st_gid)
        out.write(payload);out.flush();os.fsync(out.fileno())
    return {'encrypted_copy_verified':True,'writes':True,'source_retained':True,'runtime_cutover':False}

def main(argv=None):
    p=argparse.ArgumentParser(description='Encrypt one existing private key without overwriting/removing its source')
    p.add_argument('--source',required=True);p.add_argument('--destination',required=True)
    p.add_argument('--config',required=True);p.add_argument('--binding-path',required=True)
    p.add_argument('--apply',action='store_true');args=p.parse_args(argv)
    try:
        context,row=configuration(args.config,args.binding_path)
        backend=KMS(row['key_id'],row['region']) if args.apply else None
        print(json.dumps(migrate(args.source,args.destination,context,backend,apply=args.apply)))
        return 0
    except (SecretError,OSError):
        print(json.dumps({'migration':'failed','writes_verified':False,'source_retained':True}),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
