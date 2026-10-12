#!/usr/bin/env python3
"""Offline command-line entry point; no network or external dependencies."""
import argparse
import json
from pathlib import Path
import sys
import verifier as v
import bech32m

DEFAULT_TRUST=Path(__file__).resolve().parents[2]/'vectors'/'trust.cbor'
def directory_reader(directory):
    root=Path(directory)
    def get(path):
        p=root/path
        return p.read_bytes() if p.is_file() else None
    return get

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind',choices=('trust','request','checkpoint','served','bundle','evidence','receipt','replay'))
    parser.add_argument('artifact',type=Path)
    parser.add_argument('--trust',type=Path,default=DEFAULT_TRUST)
    parser.add_argument('--prior',type=Path,help='previous served directory to verify under the initial trust and learn from')
    parser.add_argument('--entry',type=Path,help='submitted entry bound by a receipt')
    parser.add_argument('--now',type=int,default=0,help='trusted receipt checking time; 0 skips expiry')
    parser.add_argument('--text',action='store_true',help='request artifact is Bech32m text with an optional file LF')
    args=parser.parse_args()
    try:
        t=v.trust(args.trust.read_bytes()); state=stored=stored_entries=None
        if args.prior:
            stored,state,stored_entries=v.served(directory_reader(args.prior),t)
        if args.kind=='served':
            cp,result,entries=v.served(directory_reader(args.artifact),t,state,stored,stored_entries)
            output={'checkpoint':cp,'state':result,'proven':v.proven(result,cp['time'])}
        elif args.kind=='replay':
            # A manifest supplies ordering only. The trust file supplies the anchor.
            manifest=json.loads(args.artifact.read_bytes())
            entries=[(args.artifact.parent/(e['name']+'.cbor')).read_bytes() for e in manifest['entries']]
            sys.stdout.buffer.write(v.canonical(v.replay(t,entries))); return 0
        else:
            raw=args.artifact.read_bytes()
            if args.kind=='trust': output=v.trust(raw)
            elif args.kind=='request':
                if args.text: raw=bech32m.payload(raw.decode().removesuffix('\n'))
                output=v.request(raw,t['net'])
            elif args.kind=='checkpoint': output=v.checkpoint(raw,t,state)
            elif args.kind=='bundle':
                b,cp=v.bundle(raw,t,state); output={'device':b['device'],'index':b['index'],'checkpoint':cp}
            elif args.kind=='evidence':
                e=v.evidence(raw,t,state); output={'fork':True,'version':e['version'],'size':e['size'],'split':e.get('split',0)}
            elif args.kind=='receipt': output=v.receipt(raw,t,state,args.entry.read_bytes() if args.entry else None,args.now)
        sys.stdout.buffer.write(v.canonical({'outcome':'accept','result':output})); return 0
    except v.Refusal as e:
        print(json.dumps({'outcome':e.code},separators=(',',':'))); return 1
    except (ValueError,OSError,KeyError,TypeError) as e:
        # Trust/configuration/input failures have no protocol refusal vocabulary.
        print(json.dumps({'error':str(e)},separators=(',',':'))); return 1

if __name__=='__main__': sys.exit(main())
