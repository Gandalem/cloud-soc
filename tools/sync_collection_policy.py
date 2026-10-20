"""Generate embedded discovery selectors from one reviewed catalogue. No checks run."""
from pathlib import Path
import json

ROOT=Path(__file__).resolve().parents[1]


def sync():
    c=json.loads((ROOT/'deploy/agents/security-catalog.json').read_text(encoding='utf-8'))
    def replace(name, body, start, end):
        p=ROOT/name;s=p.read_text(encoding='utf-8')
        a=s.index(start)+len(start);b=s.index(end,a)
        p.write_text(s[:a]+'\n'+body+'\n'+s[b:],encoding='utf-8')
    rows='\n'.join("    '"+k.replace("'","''")+"' = '"+v+"'" for k,v in c['windows_channels'].items())
    noise='\n'.join("    '"+k.replace("'","''")+"' = '"+v+"'" for k,v in c['windows_noise'].items())
    replace('deploy/agents/discover-windows.ps1',"$script:SecurityChannels = @{\n"+rows+"\n}\n$script:SecurityNoise = @{\n"+noise+"\n}",'# BEGIN SECURITY CHANNELS','# END SECURITY CHANNELS')
    rows='\n'.join('        { '+json.dumps(k)+', '+json.dumps(v)+' },' for k,v in c['windows_channels'].items())
    noise='\n'.join('        { '+json.dumps(k)+', '+json.dumps(v)+' },' for k,v in c['windows_noise'].items())
    replace('deploy/agents/discovery-native.cs','    internal static readonly Dictionary<string,string> SecurityChannels = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase) {\n'+rows+'\n    };\n    internal static readonly Dictionary<string,string> SecurityNoise = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase) {\n'+noise+'\n    };','// BEGIN SECURITY CHANNELS','// END SECURITY CHANNELS')
    # Shell ERE uses one backslash. Catalogue uses normal JSON escaping only.
    text="SECURITY_CORE_FILES='"+c['linux_core_files']+"'\nSECURITY_PACKAGE_FILES='"+c['linux_package_files']+"'"
    replace('deploy/agents/discover-linux.sh',text,'# BEGIN SECURITY FILES','# END SECURITY FILES')


if __name__=='__main__':sync()
