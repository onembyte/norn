#!/usr/bin/env python3
"""Offline command-line interface; all protocol decisions live in protocol.py."""
import sys
sys.dont_write_bytecode=True
import argparse
import json
from pathlib import Path
import protocol as p
import cbor


def main():
    ap=argparse.ArgumentParser(description='Independent, standard-library Norn verifier')
    ap.add_argument('--trust',type=Path,default=Path(__file__).resolve().parents[2]/'vectors/trust.cbor')
    ap.add_argument('--learn-from',type=Path,action='append',default=[],help='verify and replay this served log before checking the target; repeat for successive heads')
    sub=ap.add_subparsers(dest='command',required=True)
    for cmd in ('served','bundle','evidence','receipt','request','trust','replay','decode'):
        a=sub.add_parser(cmd); a.add_argument('path',type=Path)
        if cmd=='request': a.add_argument('--text',action='store_true')
        if cmd=='receipt':
            a.add_argument('--entry',type=Path); a.add_argument('--time',type=int,default=0)
    args=ap.parse_args()
    try:
        if args.command=='decode': result=cbor.loads(args.path.read_bytes())
        elif args.command=='trust':
            raw=args.path.read_bytes(); t=p.trust(raw)
            result={'origin':t['origin'],'fingerprint':p.fingerprint(raw).rstrip('\n')}
        elif args.command=='replay':
            m=json.loads(args.path.read_bytes()); anchor={k:bytes.fromhex(v) for k,v in m['anchor'].items()}
            entries=[]
            for i,e in enumerate(m['entries']):
                p.require(e['index']==i)
                name=e['name']; p.require('/' not in name and '\\' not in name and name not in ('.','..'))
                entries.append((args.path.parent/(name+'.cbor')).read_bytes())
            result=p.replay(anchor,entries)
        elif args.command=='request':
            raw=args.path.read_bytes()
            if args.text:
                s=raw.decode('utf-8'); s=s[:-1] if s.endswith('\n') else s
                result=p.request_text(s)
            else: result=p.request(raw)
        else:
            t=p.trust(args.trust.read_bytes()); reader=p.Reader(t); previous=None
            for source in args.learn_from:
                view=reader.served(source,stored=previous['checkpoint'] if previous else None,held_entries=previous['entries'] if previous else None)
                reader=p.Reader(t,view['state']); previous=view
            if args.command=='served':
                view=reader.served(args.path,stored=previous['checkpoint'] if previous else None,held_entries=previous['entries'] if previous else None)
                result={'checkpoint':view['checkpoint'],'state':view['state'],'proven':view['proven']}
            elif args.command=='bundle': result=reader.bundle(args.path.read_bytes())
            elif args.command=='evidence': result=reader.evidence(args.path.read_bytes())
            else:
                submitted=p.merkle.leaf(args.entry.read_bytes()) if args.entry else None
                result=reader.receipt(args.path.read_bytes(),submitted,args.time)
        sys.stdout.buffer.write(p.canonical_json(result)); return 0
    except p.Refusal as ex:
        print(ex.code,file=sys.stderr); return 1
    except cbor.DecodeError as ex:
        print('decode: '+str(ex),file=sys.stderr); return 1
    except (ValueError,OSError) as ex:
        print(str(ex),file=sys.stderr); return 1

if __name__=='__main__': sys.exit(main())
