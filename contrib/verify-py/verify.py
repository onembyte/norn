#!/usr/bin/env python3
"""Command-line interface to the offline verifier; never fetches a URL."""
import argparse
import json
from pathlib import Path
import sys
import protocol as p

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind',choices=['trust','replay','served','bundle','evidence','receipt','request'])
    parser.add_argument('path',type=Path)
    parser.add_argument('--trust',type=Path)
    parser.add_argument('--learn-from',type=Path,help='first verify this served mirror to learn keys and policy')
    parser.add_argument('--stored',type=Path,help='previously held checkpoint for served-log comparison')
    parser.add_argument('--held-log',type=Path,help='verified local branch whose entries establish the stored head')
    parser.add_argument('--entry',type=Path,help='submitted entry for receipt binding')
    parser.add_argument('--now',type=int,default=0,help='receipt checking time; zero skips expiry')
    parser.add_argument('--text',action='store_true',help='request is bech32m text instead of CBOR')
    args=parser.parse_args()
    if args.kind=='trust':
        raw=args.path.read_bytes(); result={'trust':p.trust(raw),'fingerprint':p.fingerprint(raw).removesuffix('\n')}
    else:
        if args.trust is None: parser.error('--trust is required')
        t=p.trust(args.trust.read_bytes()); accepted=None
        if args.learn_from is not None:
            _,accepted,_=p.served(p.Mirror(args.learn_from),t)
            if accepted['size']==0: raise ValueError('learning mirror has unusable genesis')
        if args.kind=='replay':
            manifest=json.loads((args.path/'manifest.json').read_bytes())
            result=p.replay(t,[(args.path/(r['name']+'.cbor')).read_bytes() for r in manifest['entries']])
        elif args.kind=='served':
            stored=p.checkpoint(args.stored.read_bytes(),t,accepted) if args.stored else None
            held_entries=None
            if args.held_log:
                held,_,held_entries=p.served(p.Mirror(args.held_log),t,accepted)
                if stored is None or (held['size'],held['root'])!=(stored['size'],stored['root']):
                    raise ValueError('--held-log must establish --stored')
            cp,state,_=p.served(p.Mirror(args.path),t,accepted,stored,held_entries)
            result={'checkpoint':{k:v for k,v in cp.items() if k!='signed'},'state':state,'proven':p.proven(state,cp['quorum_time'])}
        elif args.kind=='bundle':
            b,cp=p.bundle(args.path.read_bytes(),t,accepted)
            result={'device':b['device'],'index':b['index'],'checkpoint':{k:v for k,v in cp.items() if k!='signed'}}
        elif args.kind=='evidence':
            p.evidence(args.path.read_bytes(),t,accepted); result={'outcome':'fork'}
        elif args.kind=='receipt':
            submitted=p.merkle.leaf(args.entry.read_bytes()) if args.entry else None
            result=p.receipt(args.path.read_bytes(),t,submitted,args.now)
        elif args.kind=='request':
            result=p.request_text(args.path.read_text().removesuffix('\n'),t['net']) if args.text else p.request(args.path.read_bytes(),t['net'])
    sys.stdout.buffer.write(p.json_bytes(result))
    return 0

if __name__=='__main__':
    try: sys.exit(main())
    except p.Refusal as err:
        print(err.code,file=sys.stderr); sys.exit(1)
    except (OSError,ValueError) as err:
        print(str(err),file=sys.stderr); sys.exit(2)
