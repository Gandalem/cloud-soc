"""Offline portal user configuration. Never takes plaintext passwords in argv."""
import argparse
import getpass
import json
import os
from pathlib import Path
import tempfile

from werkzeug.security import generate_password_hash
from cloud_soc.portal.auth import load_users, ROLES


def main():
    parser = argparse.ArgumentParser(description="Create/update a single-workspace portal user; restart portal afterward")
    parser.add_argument("--file",type=Path,required=True)
    parser.add_argument("--user",required=True)
    parser.add_argument("--role",choices=sorted(ROLES),required=True)
    args=parser.parse_args()
    users=load_users(args.file) if args.file.exists() else {}
    password=getpass.getpass("New password (at least 12 characters): ")
    confirmation=getpass.getpass("Confirm password: ")
    if len(password)<12 or password!=confirmation:
        raise ValueError("Password length or confirmation invalid")
    users[args.user]={"role":args.role,"password_hash":generate_password_hash(password)}
    args.file.parent.mkdir(parents=True,exist_ok=True)
    filename=None
    try:
        with tempfile.NamedTemporaryFile(mode="w",encoding="utf-8",dir=args.file.parent,delete=False) as temporary:
            filename=Path(temporary.name)
            json.dump(users,temporary)
            temporary.flush();os.fsync(temporary.fileno())
        filename.chmod(0o600)
        load_users(filename)  # All names/roles and at least one admin checked before replacing.
        os.replace(filename,args.file)
    finally:
        if filename and filename.exists(): filename.unlink()
    print("User hash configuration saved. Keep UID 1000 ownership for Docker secrets and restart portal.")


if __name__=="__main__":
    try:
        main()
    except (ValueError,OSError) as error:
        raise SystemExit(f"User configuration not changed ({type(error).__name__}).") from None
