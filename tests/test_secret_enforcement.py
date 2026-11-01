import json,os
from pathlib import Path
from unittest.mock import Mock,patch
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cloud_soc.secret_store import encrypt,decrypt,SecretError,read,KMS,write_new
from cloud_soc.secret_migrate import migrate

CONTEXT={'tenant':'org-A','purpose':'elasticsearch','secret_id':'normalizer'}
ARN='arn:aws:kms:ap-northeast-2:123456789012:key/00000000-0000-0000-0000-000000000000'
class MemoryBackend:
    # Test-only. No production local-key backend is implemented.
    key_id=ARN
    def __init__(self):self.key=AESGCM.generate_key(bit_length=256);self.fail=False
    def generate(self,context):
        if self.fail:raise SecretError('kms_unavailable')
        return self.key,b'wrapped-test-dek'
    def unwrap(self,wrapped,context):
        if self.fail:raise SecretError('kms_unavailable')
        assert wrapped==b'wrapped-test-dek';return self.key

def private(path,content):path.write_text(content);path.chmod(0o600);return path

def test_envelope_has_no_secret_and_is_randomized_and_bound():
    b=MemoryBackend();first=encrypt('SYNTHETIC-secret-value',CONTEXT,b);second=encrypt('SYNTHETIC-secret-value',CONTEXT,b)
    assert first['nonce']!=second['nonce'] and first['ciphertext']!=second['ciphertext']
    assert 'SYNTHETIC-secret-value' not in json.dumps(first)
    assert decrypt(first,CONTEXT,b)=='SYNTHETIC-secret-value'
    for context in [{**CONTEXT,'tenant':'org-B'},{**CONTEXT,'purpose':'other'},{**CONTEXT,'secret_id':'detector'}]:
        with pytest.raises(SecretError):decrypt(first,context,b)
    damaged={**first,'ciphertext':first['ciphertext'][:-4]+'AAAA'}
    with pytest.raises(SecretError):decrypt(damaged,CONTEXT,b)
    b.fail=True
    with pytest.raises(SecretError):decrypt(first,CONTEXT,b)

def test_strict_reader_rejects_plaintext_and_never_downgrades(tmp_path,monkeypatch):
    p=private(tmp_path/'key','SYNTHETIC');monkeypatch.setenv('SOC_SECRET_POLICY','required')
    with pytest.raises(SecretError,match='plaintext_secret_forbidden'):read(p)
    p.write_text('{invalid-json')
    with pytest.raises(SecretError):read(p)
    p.write_text(json.dumps(encrypt('SYNTHETIC',CONTEXT,MemoryBackend())))
    monkeypatch.delenv('SOC_SECRET_CONFIG_FILE',raising=False)
    with pytest.raises(SecretError,match='secret_policy_required'):read(p)

def test_existing_common_reader_and_cloud_inline_rejected(tmp_path,monkeypatch):
    from cloud_soc.aws.__main__ import protected_key
    from cloud_soc.multicloud.collectors import secret
    p=private(tmp_path/'key','SYNTHETIC');monkeypatch.setenv('SOC_SECRET_POLICY','required')
    with pytest.raises(SecretError):protected_key(p)
    monkeypatch.setenv('SYNTHETIC_KEY','secret-canary')
    with pytest.raises(SecretError,match='inline_secret_forbidden'):secret('SYNTHETIC_KEY')

def test_migration_plan_and_verified_copy_leave_source_unchanged(tmp_path):
    tmp_path.chmod(0o700);p=private(tmp_path/'old','SYNTHETIC');out=tmp_path/'new';b=MemoryBackend()
    assert migrate(p,out,CONTEXT,None)['writes'] is False
    assert not out.exists()
    assert migrate(p,out,CONTEXT,b,apply=True)['runtime_cutover'] is False
    assert p.read_text()=='SYNTHETIC' and out.stat().st_mode & 0o077==0
    assert decrypt(json.loads(out.read_text()),CONTEXT,b)=='SYNTHETIC'
    with pytest.raises(SecretError):migrate(p,out,CONTEXT,b,apply=True)
    b.fail=True
    with pytest.raises(SecretError):migrate(p,tmp_path/'failed',CONTEXT,b,apply=True)
    assert not (tmp_path/'failed').exists() and p.read_text()=='SYNTHETIC'

def test_kms_context_and_key_identity_are_pinned():
    client=Mock();key=b'k'*32
    client.generate_data_key.return_value={'Plaintext':key,'CiphertextBlob':b'wrapped','KeyId':ARN}
    client.decrypt.return_value={'Plaintext':key,'KeyId':ARN}
    backend=KMS(ARN,'ap-northeast-2',client)
    env=encrypt('fixture',CONTEXT,backend);assert decrypt(env,CONTEXT,backend)=='fixture'
    assert client.decrypt.call_args.kwargs['EncryptionContext']==CONTEXT
    assert client.decrypt.call_args.kwargs['KeyId']==ARN
    client.decrypt.return_value['KeyId']='different'
    with pytest.raises(SecretError,match='kms_key_mismatch'):decrypt(env,CONTEXT,backend)

def test_encrypted_read_and_write_require_binding_and_private_files(tmp_path,monkeypatch):
    b=MemoryBackend();path=tmp_path/'key';config=private(tmp_path/'policy',json.dumps({'schema_version':1,'backend':{'type':'aws-kms','key_id':ARN,'region':'ap-northeast-2'},'bindings':{str(path):CONTEXT}}))
    monkeypatch.setenv('SOC_SECRET_CONFIG_FILE',str(config));monkeypatch.setenv('SOC_SECRET_POLICY','required')
    with patch('cloud_soc.secret_store.KMS',return_value=b):
        write_new(path,'SYNTHETIC');assert read(path,purpose='elasticsearch')=='SYNTHETIC'
        with pytest.raises(SecretError):read(path,purpose='different')
        with pytest.raises(FileExistsError):write_new(path,'REPLACE')
        path.chmod(0o644)
        with pytest.raises(SecretError):read(path)
