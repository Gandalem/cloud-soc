"""Add read-only history access while preserving current monitor credentials and roles."""
from pathlib import Path
from elasticsearch import Elasticsearch

with Elasticsearch("https://elasticsearch:9200", ca_certs="/run/ca.crt",
    basic_auth=("elastic", Path("/run/admin").read_text().strip()), request_timeout=30) as client:
    username, role = "cloud_soc_agent_monitor", "cloud_soc_history_reader"
    users = client.security.get_user(username=username)
    assert username in users and users[username].get("enabled"), "Monitor account unavailable"
    roles = users[username]["roles"]
    client.security.put_role(name=role, cluster=[], indices=[{
        "names": ["soc-normalized-history-v1", "soc-processing-history-v1"],
        "privileges": ["read", "view_index_metadata"]}])
    if role not in roles:
        client.security.put_user(username=username, roles=roles + [role])
    print("이력 2개 인덱스 읽기 권한 연결 완료 / 기존 역할·암호 유지")
