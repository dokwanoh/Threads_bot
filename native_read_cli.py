"""Four-step native READ-only bridge CLI. No browser execution or mutation flag.

The assigned native worker makes actual supported browser reads between begin and
complete. It must supply actual tool observations, never fabricated result JSON.
"""
import argparse
from dataclasses import asdict
import json
from pathlib import Path

from dispatch_gate import CommandResult, canonical, parse_json, require
from tool_bridge import (BindingPin, ClaimedRequest, FileToolBridge, INTEGRATION_ROOT,
                         RequestTicket)
from native_handler import READ_OPERATIONS, validate_prepared_action


def read_input(path):
    from publisher_safety import _file
    return parse_json(_file(str(Path(path))).decode('utf-8'))


def read_step(bridge, operation, ticket, binding, *, claimed_at=None, data=None):
    """Public results only. Each state change remains the bridge's durable API."""
    require(operation in {'inspect','claim','begin','complete'}, 'Unknown read service step')
    request=bridge.inspect(ticket)
    require(request['operation'] in READ_OPERATIONS and request['transport_mode']=='read_only',
            'Native read service refuses every mutation request')
    require(request['binding']==binding.as_dict(), 'Assigned native binding mismatch')
    if request['action'] is not None:validate_prepared_action(request['action'],binding)
    if operation=='inspect':
        require(claimed_at is None and data is None, 'Unexpected inspect arguments')
        return request
    if operation=='claim':
        require(claimed_at is None and data is None, 'Unexpected claim arguments')
        return asdict(bridge.claim(ticket,binding))
    require(type(claimed_at) is int and claimed_at>=0, 'Exact previously returned claim time required')
    claim=ClaimedRequest(ticket,binding,claimed_at)
    if operation=='begin':
        spec=bridge.begin_dispatch(claim,data)
        return {'ticket':asdict(spec.ticket),'dispatched_at':spec.dispatched_at,'request':spec.request()}
    require(type(data) is dict and set(data)=={'completed','exit_code','stdout','truncated','session_id','stderr'}
            and type(data['stdout']) is dict, 'Exact final native read result envelope required')
    bridge.complete(claim,CommandResult(**{**data,'stdout':canonical(data['stdout'])}))
    return {'completed':True,'request_id':ticket.request_id,'request_digest':ticket.request_digest}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['inspect','claim','begin','complete'])
    parser.add_argument('--root',required=True)
    parser.add_argument('--request-id',required=True)
    parser.add_argument('--request-digest',required=True)
    parser.add_argument('--binding-file',required=True)
    parser.add_argument('--claimed-at',type=int)
    parser.add_argument('--data-file')
    args=parser.parse_args(argv)
    try:
        binding=BindingPin.from_dict(read_input(args.binding_file))
        ticket=RequestTicket(args.request_id,args.request_digest)
        data=read_input(args.data_file) if args.data_file else None
        with FileToolBridge(args.root) as bridge:
            result=read_step(bridge,args.operation,ticket,binding,claimed_at=args.claimed_at,data=data)
        print(canonical({'ok':True,'result':result}))
        return 0
    except Exception:
        # Arbitrary tool/file error text can contain private data. No automatic retry.
        print(canonical({'ok':False,'error':'Read bridge step blocked; preserve state and inspect exact trusted evidence'}))
        return 2


if __name__=='__main__':raise SystemExit(main())
