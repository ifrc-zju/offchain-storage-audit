from pathlib import Path
import subprocess,sys,datetime,json
ROOT=Path(__file__).resolve().parents[1]; out=ROOT/'运行记录'; out.mkdir(exist_ok=True)
run_id=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
start=datetime.datetime.now(datetime.timezone.utc).isoformat()
command=[sys.executable,'-X','utf8',str(ROOT/'tools/test_protocol.py')]
r=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
(out/f'tests_{run_id}.log').write_bytes(r.stdout)
(out/f'tests_{run_id}.json').write_text(json.dumps(dict(started_at=start,ended_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),command=command,returncode=r.returncode)),encoding='utf-8')
print(r.stdout.decode('utf-8',errors='replace'))
sys.exit(r.returncode)
