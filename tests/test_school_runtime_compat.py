
"""School runtime compatibility: disabled cleanup, live-writer ordering and durable recovery."""
from contextlib import closing, nullcontext
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
from unittest.mock import Mock

import pytest
from cloud_soc.deployment import host
from cloud_soc.deployment.contract import ALL_WORKERS, SERVICES, build_contract
from cloud_soc.deployment.migrations import state_compatible
from test_deployment_parity import POLICY, BASE, NOW, seed

ROOT = Path(__file__).resolve().parents[1]


def cleanup_module():
    spec = importlib.util.spec_from_file_location("school_cleanup", ROOT/"deploy/server/enrollment-maintenance.py")
    result = importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


class StopLoop(BaseException):
    pass


@pytest.mark.parametrize("enabled", [None, "", "0", "false"])
def test_disabled_cleanup_waits_across_cycles_without_credentials_io(monkeypatch, enabled):
    module = cleanup_module()
    if enabled is None:monkeypatch.delenv("SOC_ENROLLMENT_ENABLED", raising=False)
    else:monkeypatch.setenv("SOC_ENROLLMENT_ENABLED", enabled)
    for name in ("SOC_CA_FILE", "SOC_ISSUER_PASSWORD_FILE", "SOC_STATE_DIR", "SOC_INTERNAL_ES_URL"):
        monkeypatch.delenv(name, raising=False)
    clients = [Mock(side_effect=AssertionError("OFF must never initialize external state")) for _ in range(3)]
    for name, mock in zip(("Elasticsearch", "PackageStore", "Enrollments"), clients):monkeypatch.setattr(module, name, mock)
    sleep = Mock(side_effect=[None, None, StopLoop()]);monkeypatch.setattr(module.time, "sleep", sleep)
    with pytest.raises(StopLoop):module.main()
    assert sleep.call_count == 3 and all(c.args == (60,) for c in sleep.call_args_list)
    assert all(not c.called for c in clients)


@pytest.mark.parametrize("upstream_failure", [False, True])
def test_enabled_cleanup_keeps_existing_sweep_and_retry(monkeypatch, tmp_path, upstream_failure):
    module = cleanup_module();password=tmp_path/"issuer";password.write_text("SYNTHETIC_ONLY")
    for k,v in {"SOC_ENROLLMENT_ENABLED":"1","SOC_CA_FILE":str(tmp_path/"ca"),"SOC_ISSUER_PASSWORD_FILE":str(password),
                "SOC_STATE_DIR":str(tmp_path),"SOC_INTERNAL_ES_URL":"https://synthetic:9200","SOC_ELASTIC_ENDPOINT":"https://synthetic:9200"}.items():monkeypatch.setenv(k,v)
    (tmp_path/"ca").write_bytes(b"SYNTHETIC CA")
    issuer, store, service = Mock(), Mock(), Mock()
    service.sweep.side_effect = [RuntimeError("isolated failure") if upstream_failure else {"cleanup_pending":True},
                                 {"cleanup_pending":False}]
    factories = [Mock(return_value=x) for x in (issuer,store,service)]
    for name,mock in zip(("Elasticsearch","PackageStore","Enrollments"),factories):monkeypatch.setattr(module,name,mock)
    monkeypatch.setattr(module.time,"sleep",Mock(side_effect=[None,StopLoop()]))
    with pytest.raises(StopLoop):module.main()
    assert service.sweep.call_count==2
    for factory in factories:factory.assert_called_once()
    assert factories[0].call_args.kwargs["basic_auth"]==("cloud_soc_issuer","SYNTHETIC_ONLY")


@pytest.mark.parametrize("state", [
    {"Running":True,"Status":"restarting"}, {"Running":True,"Restarting":True},
    {"Running":True,"OOMKilled":True}, {"Running":True,"Health":{"Status":"unhealthy"}},
    {"Running":False,"Status":"exited"},
])
def test_readiness_rejects_restart_and_oom_even_when_running_flag_is_true(state):
    assert not host.service_running({"State":state})


def service(name, image="old", memory=128):
    return {"Id":name+"-"+image,"Image":image,"State":{"Running":True,"Status":"running","OOMKilled":False},
            "Config":{"Cmd":["sleep","infinity"],"Entrypoint":None,"Env":["MODE=preserved"]},
            "HostConfig":{"Memory":memory,"PortBindings":{}},
            "Mounts":[{"Destination":"/data","Source":"/isolated/"+name,"Type":"bind","RW":True}]}


def recovery_fixture(tmp_path, monkeypatch):
    runtime=tmp_path/"server/runtime";run=runtime/"upgrades/failed";run.mkdir(parents=True)
    old={n:service(n) for n in ("portal","gateway","kibana","elasticsearch","normalizer","detector")}
    actual=deepcopy(old)
    actual["portal"]=service("portal","new")
    actual["kibana"]=service("kibana",memory=256)
    actual["detector-priority"]=service("detector-priority","new")
    saved={"previous_compose":["--project-name","cloud-soc-central","-f","old.json"],"old_names":list(old),
           "old_services":{n:host.service_signature(o) for n,o in old.items()},"old_contract":None,"old_current":None,
           "canonical":["compose","--project-name","cloud-soc-central"],"environment":{}}
    (run/"recovery.json").write_text(json.dumps(saved));(runtime/"pending.json").write_text(json.dumps({"run":str(run)}))
    (runtime/"contract.json").write_text(json.dumps({"version":2,"workers":{}}))
    db=runtime/"progress.sqlite"
    with closing(sqlite3.connect(db)) as c:c.execute("create table checkpoint(value)");c.execute("insert into checkpoint values(123)");c.commit()
    key=runtime/"worker.key";key.write_bytes(b"SYNTHETIC_ONLY");original=(db.read_bytes(),key.read_bytes())
    class Engine:
        calls=[];fail=False
        def run(self,args,**kwargs):
            self.calls.append(args)
            if args[0]=="stop":
                for n in actual:
                    if "cloud-soc-central-"+n+"-1" in args:actual[n]["State"]={"Running":False,"Status":"exited"}
            if "up" in args:
                assert "--no-deps" in args and "bootstrap" not in args
                if self.fail:raise RuntimeError("isolated compose failure")
                for n in old:
                    if n in args:actual[n]=deepcopy(old[n])
            return ""
    engine=Engine()
    monkeypatch.setattr(host,"containers",lambda *_:deepcopy(actual))
    monkeypatch.setattr(host,"worker_inventory",lambda *_:{n:o["Id"] for n,o in actual.items() if n in ALL_WORKERS and o["State"]["Running"]})
    monkeypatch.setattr(host,"lock",lambda _:nullcontext())
    return runtime,run,old,actual,engine,db,key,original


def test_recover_skips_bootstrap_and_leaves_healthy_old_workers_and_es_untouched(tmp_path,monkeypatch):
    runtime,run,old,actual,engine,db,key,original=recovery_fixture(tmp_path,monkeypatch)
    result=host.recover(engine,runtime.parent)
    assert result["old_execution_restored"] and not (runtime/"pending.json").exists()
    assert (run/"recovered.json").exists() and (runtime/"retry.json").exists()
    up=next(a for a in engine.calls if "up" in a)
    assert "elasticsearch" not in up and "normalizer" not in up and "detector" not in up
    assert "portal" in up and "kibana" in up and "gateway" not in up
    assert all("bootstrap" not in a for a in engine.calls)
    assert not actual["detector-priority"]["State"]["Running"]
    assert (db.read_bytes(),key.read_bytes())==original


def test_failed_recovery_keeps_pending_and_original_progress_and_key(tmp_path,monkeypatch):
    runtime,run,old,actual,engine,db,key,original=recovery_fixture(tmp_path,monkeypatch)
    engine.fail=True
    with pytest.raises(RuntimeError):host.recover(engine,runtime.parent)
    assert (runtime/"pending.json").exists() and not (run/"recovered.json").exists()
    assert (db.read_bytes(),key.read_bytes())==original


def test_retry_reuses_stopped_priority_identity_and_never_copies_state_onto_itself(tmp_path,ownership_calls):
    state=tmp_path/"server";runtime=state/"runtime";runtime.mkdir(parents=True)
    objects=seed(runtime/"state",("detector-priority",))
    row_contract,_=build_contract(POLICY,{},state,now=BASE.replace(second=0))
    # Use the exact original command options and fixed start from the seeded worker.
    row_contract,_=build_contract(POLICY,objects,state,now=NOW)
    run=runtime/"upgrades/failed";run.mkdir(parents=True)
    retained=run/"interrupted-contract.json";retained.write_text(json.dumps(row_contract))
    (runtime/"retry.json").write_text(json.dumps({"run":str(run),"contract_sha256":hashlib.sha256(retained.read_bytes()).hexdigest()}))
    objects["detector-priority"]["Config"]["Cmd"]=["python","-m","cloud_soc.deployment.worker","--service","detector-priority"]
    objects["detector-priority"]["State"]={"Running":False,"Status":"exited"}
    view=host.adoption_containers(objects,state)
    contract,adopt=build_contract(POLICY,view,state,now=NOW)
    path=Path(adopt["detector-priority"]["state_source"]);before=path.read_bytes()
    state_compatible(contract["workers"]["detector-priority"],path)
    host.copy_adopted_state({"adoption":{"detector-priority":adopt["detector-priority"]},"state":str(state),"contract":contract},runtime)
    assert path.read_bytes()==before and not list(path.parent.glob("*.unactivated-*"))
    assert contract["workers"]["detector-priority"]["options"]["--start"]==row_contract["workers"]["detector-priority"]["options"]["--start"]
    retained.write_text("{}")
    with pytest.raises(ValueError,match="changed"):host.adoption_containers(objects,state)


def test_mutable_dashboard_is_checked_before_portal_can_accept_new_writes(tmp_path,monkeypatch,ownership_calls):
    state=tmp_path/"server";objects=seed(state,("normalizer","detector"));contract,adopt=build_contract(POLICY,objects,state,now=NOW)
    # A first failed common deployment may leave a stopped service unknown to legacy Compose.
    objects['slack-notifier']=service('slack-notifier')
    objects['slack-notifier']['State']={'Running':False,'Status':'exited'}
    (state/"compose.env").write_text("");(state/"secrets/elastic_password").write_text("SYNTHETIC")
    portal=state/"portal";portal.mkdir()
    with closing(sqlite3.connect(portal/"dashboards.sqlite")) as db:
        db.execute("create table dashboard_collections(actor,revision,body)");db.execute("insert into dashboard_collections values('admin',15,'old')");db.commit()
    plan={"workspace":str(tmp_path),"state":str(state),"image":"fixture","image_id":"new","project":"cloud-soc-central",
          "policy":POLICY,"contract":contract,"adoption":adopt,"resources":{"ok":True},"fingerprint":"test","observed":{},
          "protected_sha256":{},"previous_compose":["-f","old.json"],"source":{},"source_sha256":"test","site":{},"fresh":False,
          "new_workers":[],"compose_environment":{}}
    class Engine:
        phase="old"
        def run(self,args,**kwargs):
            if 'stop' in args:assert 'slack-notifier' not in args
            if "up" in args and "site.json" in " ".join(args):
                self.phase="new"
                if "portal" in args:
                    with closing(sqlite3.connect(portal/"dashboards.sqlite")) as db:
                        db.execute("update dashboard_collections set revision=16,body='new authenticated save'");db.commit()
            return ""
        def json(self,args,**kwargs):
            if "config" in args:return {"services":{n:{"image":"fixture"} for n in SERVICES}}
            return {"version":2}
    engine=Engine()
    monkeypatch.setattr(host,"snapshot",lambda *_:deepcopy(plan));monkeypatch.setattr(host,"lock",lambda _:nullcontext())
    monkeypatch.setattr(host,"containers",lambda *_:objects if engine.phase=="old" else {n:service(n,"new") for n in SERVICES})
    monkeypatch.setattr(host,"worker_inventory",lambda *_,stopped=False:{} if stopped else {n:n for n in ALL_WORKERS})
    monkeypatch.setattr(host,"immutable_documents",lambda *_,**__:{"existing_immutable_documents_preserved":21})
    assert host.apply(engine,plan)["runtime_ready"]
    with closing(sqlite3.connect(portal/"dashboards.sqlite")) as db:assert db.execute("select revision from dashboard_collections").fetchone()==(16,)


def test_adoption_keeps_required_early_database_and_archives_wal_without_copying_siblings(tmp_path,ownership_calls):
    state=tmp_path/'server';source=state/'detection/runtime.sqlite';source.parent.mkdir(parents=True)
    for path in (source,Path(str(source)+'.early.sqlite'),source.parent/'unrelated.sqlite'):
        with closing(sqlite3.connect(path)) as db:db.execute('create table preserved(value)');db.execute('insert into preserved values(42)');db.commit()
    runtime=state/'runtime';target=runtime/'state/detector';target.mkdir(parents=True,mode=0o700)
    (target/source.name).write_bytes(b'old unactivated main');Path(str(target/source.name)+'-wal').write_bytes(b'old WAL bytes')
    plan={'state':str(state),'adoption':{'detector':{'state_source':str(source)}},'contract':{'workers':{'detector':{'options':{'--early-auth':True}}}}}
    files=list(host.adopted_files(plan,runtime));assert files==[('detector',[source,Path(str(source)+'.early.sqlite')])]
    original=source.read_bytes();host.copy_adopted_state(plan,runtime)
    assert (target/source.name).is_file() and (target/(source.name+'.early.sqlite')).is_file() and not (target/'unrelated.sqlite').exists()
    assert source.read_bytes()==original and not Path(str(target/source.name)+'-wal').exists()
    assert any(p.read_bytes()==b'old WAL bytes' for p in target.glob('*.unactivated-*-wal'))


def test_disk_budget_includes_retained_state_adoption_copy():
    from cloud_soc.deployment.contract import resource_check
    hardware={'cpus':4,'memory_bytes':8*1024**3,'available_memory_bytes':8*1024**3,'free_bytes':4*1024**3,'map_count':1048576}
    first=resource_check(POLICY,hardware,fresh=False,database_bytes=512*1024**2)
    second=resource_check(POLICY,hardware,fresh=False,database_bytes=512*1024**2,adoption_bytes=2*1024**3)
    assert first['ok'] and not second['ok'] and 'disk_backup_and_release_budget_exceeded' in second['issues']
