"""Standalone observe-only trial driver. No ledger, queue DB or browser access.

Trusted orchestration must coordinate the existing writer rule and assigned
native workers. An explicit protected composer binding is required.
"""
import argparse
from dataclasses import asdict
import hashlib
from pathlib import Path
import sys
import time

from dispatch_gate import canonical, parse_json, require, successful
from publisher_safety import _file
from tool_bridge import BindingPin, FileToolBridge, SlotContext, RequestTicket


def atomic_new(path,value):
    data=canonical(value).encode()
    with Path(path).open('xb') as output:
        output.write(data);output.flush()
    return hashlib.sha256(data).hexdigest()


def publish(root, bindings, reference, *, protected, now=None, duration=300):
    require(type(protected) is tuple and len(protected)==2 and
            all(type(value) is str and 0<len(value)<=512 and value==value.strip() and
                not any(ord(character)<32 for character in value) for value in protected),
            'Explicit canonical protected browser/tab binding required')
    require(protected[0].casefold() not in {'cdp','iab','extension','mcpapps'},
            'Protected browser must be a canonical instance ID, not a selection alias')
    now=int(time.time()) if now is None else now
    require(type(now) is int and type(duration) is int and 30<=duration<=300,'Bounded integer trial window required')
    require(type(bindings) is list and len(bindings) in (1,3),'One initial role or all three roles required')
    pins=[BindingPin.from_dict(value) for value in bindings]
    require(len({p.role for p in pins})==len(pins) and len({p.worker_id for p in pins})==len(pins) and
            len({(p.browser_id,p.tab_id) for p in pins})==len(pins),'Distinct actual role workers and tabs required')
    require(len(pins)==1 or {p.role for p in pins}=={'spreader','publisher','commenter'},'Exact three role set required')
    require(all((p.browser_id,p.tab_id)!=protected for p in pins),'Retained publisher composer tab is protected')
    require(type(reference) is str and reference and reference==reference.strip(),'Exact approved read-trial reference required')
    root=Path(root)
    require(root.is_dir() and not any(root.iterdir()),'Explicit empty dedicated trial directory required')
    bridge_root=root/'bridge'
    items=[]
    with FileToolBridge(bridge_root) as bridge:
        for pin in pins:
            context=SlotContext(pin,now,now+duration,reference)
            ticket=bridge.submit('observe',context,timeout_seconds=duration)
            binding_file=root/(pin.role+'-binding.json')
            atomic_new(binding_file,pin.as_dict())
            items.append({'role':pin.role,'binding_file':str(binding_file),'binding':pin.as_dict(),
                          **asdict(ticket)})
    manifest={'schema':'native-observe-trial-v1','bridge_root':str(bridge_root),
              'window_start':now,'window_deadline':now+duration,'created_at':int(time.time()),
              'authorization_reference':reference,'tickets':items}
    path=root/'TRIAL_TICKETS.json';digest=atomic_new(path,manifest)
    return {'ok':True,'stage':'awaiting_actual_native_reads','manifest':str(path),
            'manifest_sha256':digest,**manifest,'no_social_mutation':True}


def consume(manifest_path,manifest_sha256):
    raw=_file(str(Path(manifest_path)))
    require(hashlib.sha256(raw).hexdigest()==manifest_sha256,'Trusted trial manifest digest mismatch')
    manifest=parse_json(raw.decode())
    require(manifest.get('schema')=='native-observe-trial-v1','Wrong trial manifest schema')
    results=[]
    with FileToolBridge(manifest['bridge_root']) as bridge:
        for item in manifest['tickets']:
            ticket=RequestTicket(item['request_id'],item['request_digest'])
            request=bridge.inspect(ticket)
            require(request['operation']=='observe' and request['binding']==item['binding'] and
                    request['slot_start']==manifest['window_start'] and
                    request['slot_deadline']==manifest['window_deadline'], 'Trial request differs from exact observation manifest')
            result=successful(bridge.wait_result(ticket))
            response=bridge._response(ticket,request)
            results.append({'role':item['role'],'request_id':ticket.request_id,
                            'dispatched_at':response['dispatched_at'],'completed_at':response['completed_at'],
                            'accepted_at':int(time.time()),'binding':result['binding']})
    value={'ok':True,'stage':'actual_read_results_accepted','manifest_sha256':manifest_sha256,
           'results':results,'no_social_mutation':True}
    output=Path(manifest_path).parent/'TRIAL_RESULTS.json'
    digest=atomic_new(output,value)
    return {**value,'result_file':str(output),'result_sha256':digest}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='mode',required=True)
    p=sub.add_parser('publish');p.add_argument('--root',required=True);p.add_argument('--bindings-file',required=True)
    p.add_argument('--reference',required=True);p.add_argument('--duration',type=int,default=300)
    p.add_argument('--protected-browser-id',required=True);p.add_argument('--protected-tab-id',required=True)
    c=sub.add_parser('consume');c.add_argument('--manifest',required=True);c.add_argument('--sha256',required=True)
    args=parser.parse_args()
    try:
        if args.mode=='publish':
            value=publish(args.root,parse_json(_file(args.bindings_file).decode()),args.reference,duration=args.duration,
                          protected=(args.protected_browser_id,args.protected_tab_id))
        else:value=consume(args.manifest,args.sha256)
        print(canonical(value));return 0
    except Exception:
        print(canonical({'ok':False,'error':'Read trial blocked or incomplete; preserve existing ticket state, do not retry automatically'}));return 2


if __name__=='__main__':raise SystemExit(main())
