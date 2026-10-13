"""Fixed DVWA producer/export entry; no publisher credentials or network requests."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from cloud_soc.web.spool import collect, container_source, export


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',required=True);parser.add_argument('--export',action='store_true');parser.add_argument('--once',action='store_true')
    args=parser.parse_args();config=json.loads(Path(args.config).read_text());state=config.pop('state')
    if args.export:
        message=sys.stdin.buffer.read(2049)
        if len(message)>2048:raise ValueError('export_budget')
        print(json.dumps(export(state,json.loads(message))));return
    while True:
        try:
            saved=collect(container_source(config['container']),state,config,datetime.now(timezone.utc).isoformat())
            print('web_collection_observed='+str(saved['observed'])+' malformed='+str(saved['malformed'])+' source_gaps='+str(saved['source_gaps'])+' evicted='+str(saved['evicted']),flush=True)
        except Exception:
            print('web_collection_failed; cursor retained; details withheld',flush=True)
            if args.once:raise SystemExit(1)
        if args.once:return
        time.sleep(2)


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Web source/export unavailable; no source contents disclosed.') from None
