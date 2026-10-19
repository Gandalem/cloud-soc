"""Read immutable bundle settings plus explicit, bounded local switches."""
import json
from pathlib import Path
import sys
import re


def read(path):
    path=Path(path)
    if path.is_symlink():raise ValueError('Linked profile')
    profile=json.loads(path.read_text())
    if profile.get('schema')!=1 or type(profile.get('system')) is not bool or type(profile.get('network')) is not bool:
        raise ValueError('Invalid profile')
    switches=path.with_name('collection-switches.json')
    if switches.exists() or switches.is_symlink():
        if switches.is_symlink() or switches.stat().st_size>8192:raise ValueError('Invalid switches')
        data=json.loads(switches.read_text())
        if not isinstance(data,dict) or set(data)-{'system','network','web'}:raise ValueError('Invalid switches')
        for key in ('system','network'):
            if key in data:
                if type(data[key]) is not bool:raise ValueError('Invalid switch')
                profile[key]=data[key]
        web=data.get('web',{})
        if not isinstance(web,dict) or len(web)>8:raise ValueError('Invalid web switches')
        def site_id(value):
            match = re.fullmatch(r'cloud-soc-(?:site|modsecurity)-([A-Za-z0-9][A-Za-z0-9_-]{0,63})', value)
            if not match:
                raise ValueError('Unknown web input identity')
            return match[1]
        known={site_id(x['id']) for x in profile['web_inputs']}
        if set(web)-known or any(type(v) is not bool for v in web.values()):raise ValueError('Unknown site switch')
        for x in profile['web_inputs']:
            key=site_id(x['id'])
            if key in web:x['enabled']=web[key]
    return profile


if __name__=='__main__':print(json.dumps(read(sys.argv[1])))
