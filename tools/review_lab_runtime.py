"""Final real lab review, split before/after the separately requested VM reboot.

Run inside the VM. Browser login material must stay in runtime/secrets.
No mocked storage and no direct raw/normalized/alert insertion are used.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import time
from urllib.parse import quote

ROOT=Path('/home/kopo/soc-mall-lab')
R=ROOT/'live-runtime'
sys.path.insert(0,str(ROOT/'portal-lab/venv/lib/python3.12/site-packages'))
from elasticsearch import Elasticsearch
from playwright.sync_api import sync_playwright, expect
from cloud_soc.detection.engine import event_fingerprint


def poll(callback,label,seconds=90):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        value=callback()
        if value:return value
        time.sleep(.5)
    raise AssertionError('Timed out: '+label)


def main(phase):
    os.umask(0o077);proof=R/'proof';proof.mkdir(mode=0o700,exist_ok=True)
    file=proof/'flow.json'
    if phase=='pre':
        if file.exists():raise ValueError('Preserve earlier report; resume affected phase explicitly')
        tag=secrets.token_hex(4).upper()
        report={'tag':tag,'checks':[],'rules':{},'page_errors':[],
                'boot_before':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'username':'runtime-review-'+tag.lower()}
    else:report=json.loads(file.read_text())
    def save():file.write_text(json.dumps(report,ensure_ascii=False,indent=2))
    def note(text):report['checks'].append(text);save();print(text,flush=True)
    private=json.loads((R/'secrets/review-login.json').read_text())
    c=json.loads((R/'config/connection.json').read_text());scope=json.loads((ROOT/'portal-lab/config/mall-scope.json').read_text())
    norm=scope['normalized'] if isinstance(scope['normalized'],list) else [scope['normalized']]
    es=Elasticsearch(c['es_url'],api_key=(R/'secrets/reader.key').read_text().strip(),ca_certs=c['ca_file'],verify_certs=True,max_retries=0)
    origin='http://127.0.0.1:18081'
    def alerts(key):return es.search(index=scope['alerts'],query={'term':{'rule.id':key}},size=100)['hits']['hits']
    def normalized(action):return es.search(index=norm,query={'term':{'event.action':action}},size=1000)['hits']['hits']
    def verify(key):
        hits=alerts(key);assert hits
        for hit in hits:
            refs=hit['_source']['cloud_soc']['provenance']['evidence'];assert refs
            for ref in refs:
                value=es.get(index=ref['normalized']['index'],id=ref['normalized']['id'])['_source']
                value['_cloud_soc_meta']={'index':ref['normalized']['index'],'document_id':ref['normalized']['id']}
                assert event_fingerprint(value)==ref['event_hash']
                assert value['cloud_soc']['provenance']['raw']==ref['raw']
                assert es.get(index=ref['raw']['index'],id=ref['raw']['id'])['_source']['organization']['id']==value['organization']['id']=='mall-isolated'
        return len(hits)
    try:
        if phase=='post':
            poll(lambda:subprocess.run(['systemctl','--user','is-active','soc-mall-portal'],capture_output=True,text=True).stdout.strip()=='active','portal startup guard ready',120)
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            ctx=browser.new_context(locale='ko-KR',timezone_id='Asia/Seoul',viewport={'width':1440,'height':1000})
            page=ctx.new_page();page.on('pageerror',lambda e:report['page_errors'].append(str(e)))
            page.goto(origin+'/login');page.locator('[name=username]').fill(private['username']);page.locator('[name=password]').fill(private['password']);page.locator('#login-form button').click();page.wait_for_url(origin+'/')
            def api(path):
                response=ctx.request.get(origin+path);assert response.ok,(path,response.status);return response.json()
            def row(key):return next((r for r in api('/api/settings/rule-library')['rules'] if r['definition']['key']==key),None)
            shopctx=browser.new_context();shop=shopctx.new_page();shop.route('**/favicon.ico',lambda route:route.abort())
            def fail_login():
                shop.goto('http://127.0.0.1:18080/login');shop.locator('[name=username]').fill(report['username']);shop.locator('[name=password]').fill('intentionally-invalid-review-input');shop.locator('form button,form input[type=submit]').first.click();shop.wait_for_url(lambda u:'/login' in u and u.endswith('?error'))
                return json.loads((ROOT/'logs/security-audit.jsonl').read_text().splitlines()[-1])
            def attack():
                assert shop.goto('http://127.0.0.1:18080/admin').status==401
                assert shop.goto('http://127.0.0.1:18082/?keyword='+quote("1' OR '1'='1 -- ")).status==200
            if phase in ('pre','finish-pre'):
                if phase=='pre':
                    report['account']=fail_login()['account_id'];save()
                    page.goto(origin+'/settings-rules.html');page.locator('#rule-template option').first.wait_for(state='attached')
                    definitions=[('AUTH','실습 로그인 실패 3회','mall','threshold',[
                        ('event.action','login'),('event.outcome','failure'),('cloud_soc.security_mall.account_id',report['account'])]),
                        ('ACCESS','실습 관리자 접근 거부','mall','single',[
                        ('event.action','admin_view'),('event.outcome','failure'),('cloud_soc.security_mall.authorization_reason','unauthenticated')]),
                        ('WAF','실습 SQLi 의심','mall_waf','waf',[])]
                    for kind,name,source,rule_type,conditions in definitions:
                        key='RUNTIME-'+kind+'-'+report['tag']
                        page.locator('#rule-template').select_option('ssh_failures');page.locator('#rule-new').click();page.locator('#rule-source').select_option(source);page.locator('#rule-kind').select_option(rule_type);page.locator('#rule-key').fill(key);page.locator('#rule-name').fill(name)
                        if rule_type=='threshold':page.locator('#rule-count').fill('3');page.locator('#rule-window').fill('300');page.locator('#rule-cooldown').fill('0')
                        for field,value in conditions:
                            page.locator('#rule-add-condition').click();line=page.locator('.rule-condition').last;line.locator('select').nth(0).select_option(field);line.locator('input').fill(value)
                        page.locator('#rule-save').click();expect(page.locator('#rule-result')).to_have_text('규칙을 저장했습니다.');page.locator('#rule-approve').click();expect(page.locator('#rule-result')).to_have_text('규칙을 승인했습니다.');page.locator('#rule-apply').click();expect(page.locator('#rule-result')).to_have_text('적용을 요청했습니다.')
                        r=poll(lambda key=key:(v if (v:=row(key)) and v['active'] else None),'real worker active '+key,40)
                        report['rules'][kind]={'key':key,'id':r['id'],'generation':r['generation']};save()
                if phase=='finish-pre':
                    page.goto(origin+'/settings-rules.html');page.locator('#rule-template option').first.wait_for(state='attached')
                page.locator('#rule-new').click();page.locator('#rule-name').fill('입력 보존 확인');page.locator('#rule-name').focus()
                dashboard=ctx.new_page();dashboard.on('pageerror',lambda e:report['page_errors'].append(str(e)))
                dashboard.goto(origin+'/index.html');expect(dashboard.locator('[data-widget=alerts]')).to_be_visible()
                poll(lambda:dashboard.locator('#dashboard-updated').inner_text().startswith('조회 시각:'),'initial dashboard data')
                navigations=[];dashboard.on('framenavigated',lambda frame:navigations.append(frame.url) if frame==dashboard.main_frame else None)
                baseline=dashboard.locator('[data-widget=alerts]').inner_text()
                auth=report['rules']['AUTH']['key']
                counts_before={kind:len(alerts(data['key'])) for kind,data in report['rules'].items()}
                if phase=='pre':
                    fail_login()
                    poll(lambda:sum(h['_source']['cloud_soc']['security_mall']['account_id']==report['account'] for h in normalized('login'))>=2,'two failures normalized')
                    time.sleep(3);assert not alerts(auth);note('Two actual failed logins: no threshold-three alert')
                start=time.monotonic();fail_login();attack()
                for kind,data in report['rules'].items():poll(lambda kind=kind,key=data['key']:len(alerts(key))>counts_before[kind],'real alert '+data['key'])
                report['backend_latency_seconds']=round(time.monotonic()-start,3)
                assert dashboard.locator('[data-widget=alerts]').inner_text()==baseline
                pending=dashboard.locator('.live-pending').filter(has_text='새 경보');expect(pending).to_be_visible(timeout=25000)
                assert not navigations;assert page.locator('#rule-name').input_value()=='입력 보존 확인'
                pending.click()
                def all_announced():
                    text=dashboard.locator('[data-widget=alerts]').inner_text()
                    if all(data['key'] in text for data in report['rules'].values()) and text!=baseline:return True
                    if pending.is_visible():pending.click()
                    return False
                poll(all_announced,'all asynchronous alert batches announced and applied',35)
                dashboard.screenshot(path=str(proof/'pre-dashboard.png'),full_page=True)
                note('Actual AJAX update announces new alerts without page navigation; clicking applies rows and draft input remains unchanged')
                report['pre_counts']={kind:verify(data['key']) for kind,data in report['rules'].items()}
                dashboard.locator('[data-widget=alerts] a').first.click();dashboard.get_by_text('근거 로그 보기',exact=False).first.click();dashboard.get_by_role('button',name='근거 1 조회',exact=True).click();expect(dashboard.locator('body')).to_contain_text('정규화 내용 해시 일치');dashboard.screenshot(path=str(proof/'pre-evidence.png'),full_page=True)
                note('Current canonical lab indices: real raw evidence, normalization hash, dashboard investigation verified')
                # Exercise partial update pages without altering user-owned configurations.
                for path in ['logs.html','agent-status.html','collection-health.html','operations.html','cases.html','dashboard.html']:
                    view=ctx.new_page();view.on('pageerror',lambda e:report['page_errors'].append(str(e)));view.goto(origin+'/'+path);expect(view.locator('.live-controls').first).to_be_visible(timeout=25000)
                    if path=='logs.html':
                        view.locator('#log-host').fill('미저장 검색 조건');time.sleep(11);assert view.locator('#log-host').input_value()=='미저장 검색 조건'
                    if path=='dashboard.html':poll(lambda:not view.locator('#dashboard-title').inner_text().startswith('구성 조회'),'personal dashboard')
                    view.close()
                # A failed refresh must retain already confirmed alert rows.
                dashboard.goto(origin+'/index.html');expect(dashboard.locator('[data-widget=alerts]')).to_contain_text(auth)
                previous=dashboard.locator('[data-widget=alerts]').inner_text()
                dashboard.route('**/api/operations?*',lambda route:route.abort())
                dashboard.locator('.live-controls button').filter(has_text='지금 갱신').click();expect(dashboard.locator('#dashboard-error')).to_be_visible();assert dashboard.locator('[data-widget=alerts]').inner_text()==previous
                dashboard.unroute('**/api/operations?*');dashboard.locator('.live-controls button').filter(has_text='지금 갱신').click();expect(dashboard.locator('#dashboard-error')).to_be_hidden()
                note('Other live pages load; unsaved log filter is retained; failed AJAX refresh keeps the previous alert list')
                report['recent_start']=json.loads((R/'config/recent.json').read_text())['start']
                with sqlite3.connect(R/'state/recent.sqlite') as db:report['recent_checkpoint_before']=db.execute('SELECT checkpoint FROM state').fetchone()[0]
                assert not report['page_errors'],report['page_errors'];report['pre_passed']=True;save();note('Final review before reboot passed; rules left active for restart acceptance')
            else:
                assert report['pre_passed'] and Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=report['boot_before']
                report['boot_after']=Path('/proc/sys/kernel/random/boot_id').read_text().strip();save()
                for unit in ['soc-mall-app','soc-mall-waf','soc-mall-portal','soc-mall-normalizer','soc-mall-normalizer-priority','soc-mall-managed','soc-mall-edge-projector','soc-mall-filebeat-app','soc-mall-filebeat-edge']:
                    poll(lambda unit=unit:subprocess.run(['systemctl','--user','is-active',unit],capture_output=True,text=True).stdout.strip()=='active','automatic startup '+unit,120)
                assert json.loads((R/'config/recent.json').read_text())['start']==report['recent_start']
                for data in report['rules'].values():
                    r=poll(lambda key=data['key']:(v if (v:=row(key)) and v['active'] else None),'restored active rule',90)
                    assert r['id']==data['id'] and r['generation']==data['generation']
                # Replayed input alone must not create a second stored alert.
                time.sleep(6)
                for kind,data in report['rules'].items():assert len(alerts(data['key']))==report['pre_counts'][kind]
                note('Real VM boot changed; nine enabled services and persisted rule identities recover without replay duplicates')
                # Three fresh failures: reboot duration must not supply window context.
                fail_login();fail_login();fail_login();attack()
                for kind,data in report['rules'].items():poll(lambda kind=kind,key=data['key']:len(alerts(key))>report['pre_counts'][kind],'new post-boot alert '+kind)
                report['post_counts']={kind:verify(data['key']) for kind,data in report['rules'].items()}
                note('After reboot: real login/access/SQLi -> original collectors -> recent normalizer -> managed alerts and exact evidence')
                page.goto(origin+'/index.html');expect(page.locator('[data-widget=alerts]')).to_contain_text(report['rules']['AUTH']['key']);page.screenshot(path=str(proof/'post-dashboard.png'),full_page=True)
                page.goto(origin+'/settings-rules.html');page.locator('#rule-template option').first.wait_for(state='attached')
                for data in report['rules'].values():
                    page.locator('#rule-search').fill(data['key']);expect(page.locator('#rule-list article')).to_have_count(1);page.locator('#rule-list article').get_by_role('button',name='상세 보기').click();page.once('dialog',lambda dialog:dialog.accept());page.locator('#rule-delete').click();expect(page.locator('#rule-result')).to_have_text('삭제 요청을 저장했습니다.');poll(lambda key=data['key']:row(key) is None,'worker deleted '+data['key'],40)
                    page.locator('#rule-search').fill('')
                before={action:len(normalized(action)) for action in ['login','admin_view','waf_rule_match']}
                assert fail_login()['account_id']==report['account'];attack()
                for action,n in before.items():poll(lambda action=action,n=n:len(normalized(action))>n,'ingestion after deletion '+action)
                time.sleep(5)
                for kind,data in report['rules'].items():assert len(alerts(data['key']))==report['post_counts'][kind]
                note('After reboot, UI deletion acknowledged; same matching events still ingested but no extra alerts; historical evidence retained')
                page.screenshot(path=str(proof/'post-deleted.png'),full_page=True)
                assert not report['page_errors'],report['page_errors'];report['post_passed']=True;save()
            browser.close()
    except Exception as error:
        report['failed_phase']=phase;report['failure_type']=type(error).__name__;report['failure']=str(error)[:1800];save();print('REVIEW FAILED: '+type(error).__name__+': '+str(error)[:500],flush=True);raise
    finally:es.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--phase',choices=['pre','finish-pre','post'],required=True);args=parser.parse_args();main(args.phase)
