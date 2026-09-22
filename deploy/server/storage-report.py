"""Run explicitly inside the bootstrap container; outputs metadata, never secrets."""
import argparse
import json
import os
from pathlib import Path

from elasticsearch import Elasticsearch
from cloud_soc.portal.storage import survey, growth


def main():
    parser = argparse.ArgumentParser(description='Read-only storage survey; no deletion or ILM changes')
    parser.add_argument('--proposed-days', required=True, type=int)
    parser.add_argument('--previous', type=Path)
    args = parser.parse_args()
    with Elasticsearch(os.environ['SOC_INTERNAL_ES_URL'], ca_certs=os.environ['SOC_CA_FILE'],
                       basic_auth=('elastic', Path('/run/secrets/elastic_password').read_text().strip())) as es:
        result = survey(es, days=args.proposed_days)
    if args.previous:
        if args.previous.stat().st_size > 2 * 1024 * 1024:
            raise ValueError('Previous report is too large')
        result['growth'] = growth(json.loads(args.previous.read_text(encoding='utf-8-sig')), result)
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Storage survey failed; check permissions, connectivity and inputs. Details withheld.') from None
