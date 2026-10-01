#!/usr/bin/env python3
"""Run the current acceptance corpus replacing the historical defect repro."""
import argparse,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--idf',default=os.environ.get('IDF_PATH'));a=p.parse_args()
if not a.idf:p.error('pass --idf or set IDF_PATH')
r=Path(__file__).resolve().parents[2]
subprocess.run(['bash',str(r/'tools/test-gateway.sh')],cwd=r,env={**os.environ,'IDF_PATH':a.idf},check=True)
