#!/usr/bin/env python3
"""List model tags from the chosen Ollama server; sends no emails."""
import argparse
import json
import os
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from phishbench.ollama_backend import Ollama,BackendError


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base-url',default=os.getenv('OLLAMA_BASE_URL'))
    p.add_argument('--allow-remote',action='store_true')
    p.add_argument('--model',nargs='*',help='Also check whether these exact model tags are listed')
    args=p.parse_args()
    if not args.base_url:p.error('Supply --base-url or set OLLAMA_BASE_URL')
    models=Ollama(args.base_url,allow_remote=args.allow_remote).tags()
    print(json.dumps({'base_url':args.base_url,'models':models},indent=2))
    missing=set(args.model or [])-set(models)
    if missing:
        raise ValueError('Requested model tags are not listed by this Ollama server: '+', '.join(sorted(missing)))
    return 0


if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,BackendError) as exc:
        print('Ollama check failed: '+str(exc),file=sys.stderr)
        sys.exit(1)
