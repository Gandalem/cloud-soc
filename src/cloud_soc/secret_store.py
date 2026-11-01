"""Versioned AEAD envelopes. KMS key and per-workload bindings are external policy.

Compatibility is explicit: SOC_SECRET_POLICY=required rejects all plaintext reads.
No local master key, network downgrade, or automatic plaintext fallback exists.
"""
import base64
import json
import os
from pathlib import Path
import re
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = 'cloud-soc-secret-v1'
LIMIT = 65536

class SecretError(ValueError):
    pass

def _fail(code):
    raise SecretError(code) from None

def private_bytes(path, limit=LIMIT):
    path=Path(path)
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):_fail('secret_path_unsafe')
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size>limit or (os.name=='posix' and info.st_mode & 0o077):_fail('secret_file_unsafe')
            value=f.read(limit+1)
        if len(value)>limit:_fail('secret_file_too_large')
        return value
    except SecretError:raise
    except OSError:_fail('secret_file_unavailable')

def _context(value):
    if not isinstance(value,dict) or set(value)!={'tenant','purpose','secret_id'}:_fail('secret_binding_invalid')
    if any(not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',v) for v in value.values()):_fail('secret_binding_invalid')
    return dict(value)

def _aad(context,key_id):
    return json.dumps({'format':FORMAT,'binding':_context(context),'key_id':key_id},sort_keys=True,separators=(',',':')).encode()

def _encode(v):return base64.b64encode(v).decode('ascii')
def _decode(v):
    if not isinstance(v,str):_fail('secret_envelope_invalid')
    try:return base64.b64decode(v,validate=True)
    except (ValueError,TypeError):_fail('secret_envelope_invalid')

class KMS:
    def __init__(self,key_id,region,client=None):
        if not isinstance(key_id,str) or not re.fullmatch(r'arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+',key_id):_fail('kms_key_arn_required')
        if not isinstance(region,str) or key_id.split(':')[3]!=region:_fail('kms_region_mismatch')
        self.key_id=key_id
        if client is not None:self.client=client;return
        try:
            import boto3
            session=boto3.Session(region_name=region)
            creds=session.get_credentials()
            if creds is None or creds.method not in ('iam-role','container-role','assume-role-with-web-identity'):_fail('kms_workload_identity_required')
            self.client=session.client('kms',region_name=region)
        except SecretError:raise
        except Exception:_fail('kms_unavailable')
    def generate(self,context):
        try:
            r=self.client.generate_data_key(KeyId=self.key_id,KeySpec='AES_256',EncryptionContext=context)
            if r.get('KeyId')!=self.key_id or len(r['Plaintext'])!=32:_fail('kms_key_mismatch')
            return r['Plaintext'],r['CiphertextBlob']
        except SecretError:raise
        except Exception:_fail('kms_generate_failed')
    def unwrap(self,wrapped,context):
        try:
            r=self.client.decrypt(KeyId=self.key_id,CiphertextBlob=wrapped,EncryptionContext=context)
            if r.get('KeyId')!=self.key_id or len(r['Plaintext'])!=32:_fail('kms_key_mismatch')
            return r['Plaintext']
        except SecretError:raise
        except Exception:_fail('kms_decrypt_failed')

def encrypt(value,context,backend):
    context=_context(context)
    if not isinstance(value,str) or not value or len(value.encode())>16384:_fail('secret_value_invalid')
    key,wrapped=backend.generate(context);nonce=os.urandom(12)
    try:cipher=AESGCM(key).encrypt(nonce,value.encode(),_aad(context,backend.key_id))
    finally:del key
    return {'format':FORMAT,'binding':context,'key_id':backend.key_id,'wrapped_dek':_encode(wrapped),'nonce':_encode(nonce),'ciphertext':_encode(cipher)}

def decrypt(envelope,context,backend):
    context=_context(context)
    if (not isinstance(envelope,dict) or set(envelope)!={'format','binding','key_id','wrapped_dek','nonce','ciphertext'} or envelope['format']!=FORMAT or envelope['binding']!=context or envelope['key_id']!=backend.key_id):_fail('secret_binding_mismatch')
    nonce=_decode(envelope['nonce']);wrapped=_decode(envelope['wrapped_dek']);cipher=_decode(envelope['ciphertext'])
    if len(nonce)!=12 or not wrapped or len(cipher)<17:_fail('secret_envelope_invalid')
    key=backend.unwrap(wrapped,context)
    try:
        value=AESGCM(key).decrypt(nonce,cipher,_aad(context,backend.key_id)).decode()
        if not value:_fail('secret_value_invalid')
        return value
    except Exception:_fail('secret_integrity_failed')
    finally:del key

def configuration(path,binding_path):
    try:
        conf=json.loads(private_bytes(path))
        if set(conf)!={'schema_version','backend','bindings'} or type(conf['schema_version']) is not int or conf['schema_version']!=1:_fail('secret_policy_invalid')
        row=conf['backend']
        if set(row)!={'type','key_id','region'} or row['type']!='aws-kms':_fail('secret_backend_unsupported')
        context=_context(conf['bindings'][str(binding_path)])
        return context,row
    except SecretError:raise
    except Exception:_fail('secret_policy_invalid')

def backend_for(path):
    conf=os.environ.get('SOC_SECRET_CONFIG_FILE')
    if not conf:_fail('secret_policy_required')
    context,row=configuration(conf,path)
    return context,KMS(row['key_id'],row['region'])

def required():
    policy=os.environ.get('SOC_SECRET_POLICY','legacy')
    if policy not in ('legacy','required'):_fail('secret_policy_invalid')
    return policy=='required'

def read(path,*,purpose=None):
    raw=private_bytes(path)
    if raw.lstrip().startswith(b'{'):
        try:envelope=json.loads(raw)
        except Exception:_fail('secret_envelope_invalid')
        context,backend=backend_for(path)
        if purpose and context['purpose']!=purpose:_fail('secret_purpose_mismatch')
        return decrypt(envelope,context,backend)
    if required():_fail('plaintext_secret_forbidden')
    try:return raw.decode().strip()
    except UnicodeError:_fail('secret_value_invalid')

def write_new(path,value,*,uid=None):
    context,backend=backend_for(path)
    payload=json.dumps(encrypt(value,context,backend),sort_keys=True).encode()+b'\n'
    path=Path(path)
    if path.parent.is_symlink() or any(p.is_symlink() for p in path.parents):_fail('secret_path_unsafe')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        if uid is not None:os.fchown(f.fileno(),uid,uid)
        f.write(payload);f.flush();os.fsync(f.fileno())
