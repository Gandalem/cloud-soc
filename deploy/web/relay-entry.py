"""Run only the explicitly configured web-only SSH pull publisher."""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from cloud_soc.web.relay import run_once


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',required=True);parser.add_argument('--once',action='store_true')
    args=parser.parse_args();config=json.loads(Path(args.config).read_text())
    while True:
        try:print(json.dumps(run_once(config)),flush=True)
        except Exception:
            print('web_relay_failed; cursor retained; no credentials or source contents disclosed',flush=True)
            if args.once:raise SystemExit(1)
        if args.once:return
        time.sleep(10)


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Web relay configuration unavailable; details withheld.') from None
