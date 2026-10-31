import bootstrap
import protocol as p
from pathlib import Path
import sys,csv,json,collections,random,time,zipfile,hashlib
ROOT=Path(__file__).resolve().parents[1]
def main(rid):
    inp=ROOT/'I12-INPUT/数据'/rid;res=ROOT/'I12-RESULTS/数据'/rid
    begun=p.stamp();errors=[];checks=collections.Counter()
    challenges={x['trial_id']:x for x in (json.loads(line) for line in (inp/'challenges.jsonl').open(encoding='utf-8'))}
    measurements={(r['trial_id'],r['method']):r for r in csv.DictReader((res/'measurements.csv').open(encoding='utf-8-sig'))}
    cache={};nonce_pairs=set();catalog=p.load_json(inp/'file_catalog.json')
    for info in catalog:
        directory=inp/info['input_relative'];pub=p.load_json(directory/'public.json')
        cache[info['file_key']]={'sw':pub,'ed25519':p.load_json(directory/'public_ed25519.json')}
        p.validate_public(pub,pub['signing_public'])
        if directory.joinpath('payload.bin').read_bytes()!=random.Random(info['seed']).randbytes(info['size_bytes']):errors.append('payload seed mismatch '+info['file_key'])
        checks['payload_regenerated']+=1
        secrets_data=p.load_json(directory/'test_only_secrets.json');kn=(secrets_data['aes_key'],pub['nonce'])
        if kn in nonce_pairs:errors.append('AES key/nonce pair reuse')
        nonce_pairs.add(kn)
        for a in p.load_json(directory/'allocation.json'):
            data=(directory/a['path']).read_bytes()
            if len(data)!=a['bytes'] or p.sha(data)!=a['sha256']:errors.append('block integrity '+a['path'])
            checks['blocks_hash_checked']+=1
        # Independently select alternate k survivors, recover and decrypt full ciphertext.
        keep=list(range(pub['nodes']-pub['k'],pub['nodes']))
        if not p.reconstruct(directory,pub,keep):errors.append('reconstruction '+info['file_key'])
        checks['alternate_survivor_reconstructions']+=1
    for line in (res/'proofs.jsonl').open(encoding='utf-8'):
        record=json.loads(line);key=(record['trial_id'],record['method']); row=measurements[key];qrecord=challenges[key[0]];c=qrecord['challenge'];pub=cache[qrecord['file_key']][key[1]];response=record['response']
        if record['policy']:
            session=p.SessionVerifier(pub,pub['signing_public'])
            if record['policy']=='replay':session.verify(c,response,key[1]); actual,reason=session.verify(c,response,key[1])
            else:actual,reason=session.verify(c,response,key[1],elapsed_ms=2,timeout_ms=1)
        else:actual,reason=p.verify(pub,pub['signing_public'],c,response,key[1])
        if actual!=bool(int(row['accepted'])) or actual!=record['accepted'] or reason!=row['reason']:errors.append('verification replay '+str(key))
        for field,value in [('challenge_wire_bytes',len(p.wire(c))),('proof_wire_bytes',len(p.wire(response))),('client_metadata_bytes',len(p.wire(pub)))]:
            if int(row[field])!=value:errors.append('byte count '+str(key)+' '+field)
        if int(row['total_wire_bytes'])!=len(p.wire(c))+len(p.wire(response)):errors.append('total bytes '+str(key))
        checks['proofs_reverified']+=1
        if checks['proofs_reverified']%500==0: print('reverified',checks['proofs_reverified'],flush=True)
    if len(measurements)!=checks['proofs_reverified'] or len(measurements)!=2*len(challenges): errors.append('record count mismatch')
    with zipfile.ZipFile(res/'code_snapshot.zip') as z:
        versions=p.load_json(res/'code_version.json')['files']
        for name,digest in versions.items():
            if p.sha(z.read(name))!=digest:errors.append('code snapshot '+name)
            checks['code_snapshot_files']+=1
    # Independent statistics check: raw accepted count for every published detection cell.
    for row in csv.DictReader((res/'analysis/detection_summary.csv').open(encoding='utf-8-sig')):
        sub=[r for r in measurements.values() if r['phase']=='fault' and all(r[k]==row[k] for k in ['method','case','population','damaged','q'])]
        if len(sub)!=int(row['n']) or sum(1-int(x['accepted']) for x in sub)!=int(row['detected']):errors.append('summary inconsistency')
        checks['detection_summary_cells']+=1
    result=dict(run_id=rid,started_at=begun,ended_at=p.stamp(),passed=not errors,checks=dict(checks),errors=errors)
    target=res/'verification_report.json'
    if target.exists(): target=ROOT/'复核运行'/rid/('main_'+str(time.time_ns())+'.json')
    p.save_json(target,result);print(json.dumps(result,ensure_ascii=False));return 0 if not errors else 1
if __name__=='__main__':sys.exit(main(sys.argv[1]))
