"""Read-only five-minute comparison; credentials stay in process memory."""
import argparse
import base64
from collections import Counter
from datetime import datetime, timedelta, timezone
import getpass
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

WORKERS=('detector','additional_detector','priority_detector','late_review','priority_normalizer')

def stamp(value):
    try:
        return datetime.fromisoformat(value.replace('Z','+00:00'))
    except (AttributeError, ValueError):
        return None

def snapshot(data):
    for name in ('normalizer',*WORKERS):
        row=data if name=='normalizer' else data.get(name,{})
        if not isinstance(row,dict):continue
        print(f"{name}: state={row.get('state')} health={row.get('health')} error={row.get('error')}")
        print(f"  checkpoint={row.get('checkpoint')} lag_seconds={row.get('lag_seconds')} excluded_total={row.get('excluded_total')}")
    print('coverage:',json.dumps(data.get('coverage'),ensure_ascii=False))
    print('realtime_coverage:',json.dumps(data.get('realtime_coverage'),ensure_ascii=False),flush=True)

def compare(before,after):
    for name in WORKERS:
        old,new=before.get(name,{}),after.get(name,{})
        if not isinstance(old,dict) or not isinstance(new,dict):continue
        a,b=stamp(old.get('checkpoint')),stamp(new.get('checkpoint'))
        advance=(b-a).total_seconds() if a and b else None
        x,y=old.get('lag_seconds'),new.get('lag_seconds')
        decrease=x-y if type(x)is int and type(y)is int else None
        x,y=old.get('excluded_total'),new.get('excluded_total')
        added=y-x if type(x)is int and type(y)is int else None
        verdict=('처리 위치 전진' if advance is not None and advance>0 else
                 '처리 위치 동일' if advance==0 else '처리 위치 비교 불가/역행 확인 필요')
        print(f'{name}: {verdict}; 전진={advance}초; 지연 감소={decrease}초; 제외 증가={added}건')
    print('지연 감소가 양수면 따라잡는 중, 음수면 지연이 늘어난 것입니다. 음수 제외 증가는 재시작/집계 기준 변경을 확인하세요.')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin',default='https://192.168.38.131')
    parser.add_argument('--ca',default='/home/lyn/cloud-soc/state/server/tls/ca.crt')
    parser.add_argument('--user',default='admin')
    parser.add_argument('--seconds',type=int,default=300)
    args=parser.parse_args()
    if not 1<=args.seconds<=300:parser.error('seconds must be 1..300')
    url=urllib.parse.urlsplit(args.origin)
    if url.scheme!='https' or url.username or url.password or url.path or url.query or url.fragment:
        parser.error('HTTPS origin only')
    context=ssl.create_default_context(cafile=args.ca)
    password=getpass.getpass('Portal 관리자 비밀번호 (Ubuntu 암호와 별개): ')
    authorization='Basic '+base64.b64encode((args.user+':'+password).encode()).decode()
    del password
    # Refuse redirects so credentials cannot be forwarded elsewhere.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**kw):return None
    opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=context))
    def fetch(path):
        request=urllib.request.Request(args.origin+path,headers={'Authorization':authorization,'Accept':'application/json'})
        with opener.open(request,timeout=20) as response:return json.load(response)
    print('\n=== 시작 상태 ===',flush=True)
    before=fetch('/api/operations/status');snapshot(before)
    print(f'\n{args.seconds}초 대기합니다. Ctrl+C는 관찰만 종료합니다.',flush=True)
    time.sleep(args.seconds)
    print('\n=== 종료 상태 ===',flush=True)
    after=fetch('/api/operations/status');snapshot(after)
    print('\n=== 전후 비교 ===');compare(before,after)
    print('\n=== 최근 24시간 제외 사유 표본 (최신 최대100건) ===',flush=True)
    end=datetime.now(timezone.utc)
    params=urllib.parse.urlencode({'kind':'exclusions','limit':'100','start':(end-timedelta(days=1)).isoformat(),'end':end.isoformat()})
    try:
        history=fetch('/api/detection/history?'+params)
    except urllib.error.HTTPError as error:
        print(f'제외 이력 조회 실패: HTTP {error.code}. 상태 비교 결과는 위에 표시됐습니다.');return
    rows=history.get('rows',[])
    groups=Counter((str(r.get('rule',{}).get('id','미분류')),str(r.get('reason','미기록')),
                    ','.join(map(str,r.get('missing_fields',[])))) for r in rows)
    for (rule,reason,fields),count in groups.most_common():
        print(f'{count}건 | rule={rule} | reason={reason} | missing_fields={fields or "없음"}')
    if not rows:print('조회 기간의 제외 이력 없음. 누적 excluded_total이 0이라는 뜻은 아닙니다.')
    if history.get('next'):print('추가 이력이 있습니다. 위 분포는 전체 통계가 아닌 최신100건 표본입니다.')

if __name__=='__main__':
    try:main()
    except urllib.error.HTTPError as error:raise SystemExit(f'API 조회 실패: HTTP {error.code}. 401이면 Portal 암호/계정을 확인하세요.')
    except KeyboardInterrupt:raise SystemExit('관찰 종료. 운영 서비스는 계속 실행됩니다.')
    except (OSError,ValueError) as error:raise SystemExit('인증서/연결/응답 오류: '+type(error).__name__+' (인증정보 출력 생략)')
