# SPDX-License-Identifier: Apache-2.0
"""Read the exact immutable launcher contract without starting any broker."""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
import argparse,hashlib,json,re,stat
from pathlib import Path

LAUNCHER_SHA256=_integrity_value('pin_d9bbb942cec3')
GEN_PROTOCOL='integrity-memory/broker-generation/v1'
ACTIVE_PROTOCOL='integrity-memory/active-broker-generation/v1'
FILES={'broker':'integrity-client-turn-broker.py','tools':'integrity-client-tools.json','turn_envelope':'integrity_client_turn_envelope.py'}
SHA=re.compile('[a-f0-9]{64}\\Z')
sha=lambda data:hashlib.sha256(data).hexdigest()
canonical=lambda value:json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()

def read(path,limit):
    for member in (path,*path.parents):
        info=member.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('broker_contract_reparse_denied')
    before=path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size>limit:raise ValueError('broker_contract_file_invalid')
    raw=path.read_bytes();after=path.stat()
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
        raise ValueError('broker_contract_file_changed')
    if len(raw)!=before.st_size:raise ValueError('broker_contract_file_changed')
    return raw

def generation_identity(manifest):
    if (not isinstance(manifest,dict) or set(manifest)!={'protocol','files','generation_id'}
            or manifest['protocol']!=GEN_PROTOCOL or not isinstance(manifest['files'],dict)
            or set(manifest['files'])!=set(FILES)):
        raise ValueError('broker_contract_manifest_invalid')
    for key,name in FILES.items():
        row=manifest['files'][key]
        if (not isinstance(row,dict) or set(row)!={'name','bytes','sha256'} or row['name']!=name
                or type(row['bytes']) is not int or not 0<row['bytes']<=4*1024*1024
                or not isinstance(row['sha256'],str) or not SHA.fullmatch(row['sha256'])):
            raise ValueError('broker_contract_member_invalid')
    expected=sha(canonical({'protocol':GEN_PROTOCOL,'files':manifest['files']}))
    if manifest['generation_id']!=expected:raise ValueError('broker_contract_generation_identity_invalid')
    return expected

def selection(launcher,flat_contract):
    launcher=Path(launcher).absolute();flat_contract=Path(flat_contract).absolute()
    if launcher.name!='integrity-client-turn-broker.py' or sha(read(launcher,4*1024*1024))!=LAUNCHER_SHA256:
        raise ValueError('broker_contract_launcher_pin')
    root=launcher.parent
    if flat_contract!=root/'integrity-client-tools.json':raise ValueError('broker_contract_root_binding')
    pointer_path=root/'active-broker-generation.json'
    pointer_raw=read(pointer_path,65536);pointer=json.loads(pointer_raw)
    if (not isinstance(pointer,dict) or set(pointer)!={'protocol','generation_id','manifest_sha256'}
            or pointer['protocol']!=ACTIVE_PROTOCOL or not pointer_raw.endswith(b'\n')
            or not isinstance(pointer['generation_id'],str) or not SHA.fullmatch(pointer['generation_id'])
            or not isinstance(pointer['manifest_sha256'],str) or not SHA.fullmatch(pointer['manifest_sha256'])):
        raise ValueError('broker_contract_pointer_invalid')
    folder=root/'generations'/pointer['generation_id']
    manifest_raw=read(folder/'manifest.json',65536);manifest=json.loads(manifest_raw)
    if sha(manifest_raw)!=pointer['manifest_sha256']:raise ValueError('broker_contract_manifest_digest')
    gen=generation_identity(manifest)
    if gen!=pointer['generation_id']:raise ValueError('broker_contract_pointer_generation')
    payloads={}
    for key,name in FILES.items():
        payload=read(folder/name,4*1024*1024);row=manifest['files'][key]
        if len(payload)!=row['bytes'] or sha(payload)!=row['sha256']:raise ValueError('broker_contract_member_digest')
        payloads[key]=payload
    tools=json.loads(payloads['tools'])
    if (not isinstance(tools,list) or not tools or any(not isinstance(x,dict) or not isinstance(x.get('name'),str)
            or re.fullmatch('integrity_[a-z0-9_]{1,80}',x['name']) is None for x in tools)):
        raise ValueError('broker_contract_tools_invalid')
    names=[x['name'] for x in tools]
    if len(set(names))!=len(names):raise ValueError('broker_contract_tools_duplicate')
    if read(pointer_path,65536)!=pointer_raw:raise ValueError('broker_contract_pointer_changed')
    return {'protocol':'integrity/broker-contract-selection/v1','generation_id':gen,
            'pointer_path':str(pointer_path),'pointer_sha256':sha(pointer_raw),
            'manifest_sha256':sha(manifest_raw),'tools_path':str(folder/FILES['tools']),
            'tools_sha256':manifest['files']['tools']['sha256'],'names':names,
            'state_writes':0,'brokers_started':0}

def main():
    p=argparse.ArgumentParser();p.add_argument('--launcher',required=True);p.add_argument('--flat-contract',required=True)
    args=p.parse_args()
    try:result=selection(args.launcher,args.flat_contract)
    except (OSError,ValueError,TypeError,KeyError):
        print(json.dumps({'protocol':'integrity/broker-contract-selection/v1','error':'broker_contract_selection_unavailable'}));return 1
    print(json.dumps(result,ensure_ascii=False));return 0

if __name__ == "__main__":
    _integrity_require_config()

if __name__=='__main__':raise SystemExit(main())
