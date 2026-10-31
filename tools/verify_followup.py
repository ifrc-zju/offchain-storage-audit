import bootstrap
import protocol as p
from pathlib import Path
import sys,json,csv,collections,hashlib,math,zipfile,time
from analyze_results import wilson
ROOT=Path(__file__).resolve().parents[1]
def main(rid):
    pi=ROOT/'I12-INPUT/数据'/rid;pr=ROOT/'I12-RESULTS/数据'/rid;inp=pi/'sampling_followup';out=pr/'sampling_followup'
    artifact_out=out
    if (out/'verification_report.json').exists():
        artifact_out=ROOT/'复核运行'/rid/('followup_'+str(time.time_ns()));artifact_out.mkdir(parents=True)
    start=p.stamp();errors=[];count=0;cache={}
    qs={x['trial_id']:x for x in (json.loads(line) for line in (inp/'challenges.jsonl').open(encoding='utf-8'))}
    rows={x['trial_id']:x for x in csv.DictReader((out/'measurements.csv').open(encoding='utf-8-sig'))}
    for line in (out/'proofs.jsonl').open(encoding='utf-8'):
        rec=json.loads(line);qr=qs[rec['trial_id']];row=rows[rec['trial_id']];c=qr['challenge']
        key=qr['file_key']
        if key not in cache:cache[key]=p.load_json(pi/'files'/key/'public.json')
        pub=cache[key];actual,reason=p.verify(pub,pub['signing_public'],c,rec['response'])
        if actual!=rec['accepted'] or int(actual)!=int(row['accepted']) or reason!=row['reason']:errors.append(rec['trial_id']+' proof mismatch')
        for field,value in [('challenge_wire_bytes',len(p.wire(c))),('proof_wire_bytes',len(p.wire(rec['response'])))]:
            if int(row[field])!=value:errors.append(rec['trial_id']+' wire bytes')
        # Recompute expected hit independently from raw challenge and fault set.
        hit=bool({tuple(x) for x in qr['fault']['blocks']}.intersection((x['node'],x['index']) for x in c['pairs']))
        if hit!=bool(int(row['expected_detected'])) or actual==hit:errors.append(rec['trial_id']+' expected outcome')
        count+=1
        if count%500==0:print('followup reverified',count,flush=True)
    intervals=[]
    for s in csv.DictReader((out/'detection_summary.csv').open(encoding='utf-8-sig')):
        items=[x for x in rows.values() if all(x[k]==s[k] for k in ['N','D','q'])];k=sum(int(x['detected']) for x in items)
        if len(items)!=int(s['n']) or k!=int(s['detected']):errors.append('followup summary mismatch')
        N,D,q=map(int,[s['N'],s['D'],s['q']]);theory=1-(math.comb(N-D,q)/math.comb(N,q) if q<=N-D else 0)
        if abs(theory-float(s['theory']))>1e-12:errors.append('theory mismatch')
        lo,hi=wilson(k,len(items));intervals.append(dict(N=N,D=D,q=q,n=len(items),detected=k,rate=k/len(items),theory=theory,wilson95_low=lo,wilson95_high=hi))
    with (artifact_out/'detection_with_intervals.csv').open('x',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(intervals[0]));w.writeheader();w.writerows(intervals)
    # Two implementations verify a preserved artifact, not merely newly generated test data.
    from py_ecc.bls.hash_to_curve import hash_to_G1,hash_to_G2
    from py_ecc.bls.point_compression import decompress_G1,decompress_G2
    from py_ecc.optimized_bls12_381 import multiply,add,Z1,pairing
    first=next(iter(qs.values()));pub=cache[first['file_key']];challenge=first['challenge']
    rec=json.loads(next((out/'proofs.jsonl').open(encoding='utf-8')));proof=next(x for x in rec['response']['nodes'] if x['status']=='ok')
    node=proof['node'];acc=Z1;name=pub['node_tags'][node]['descriptor']['name']
    for item in challenge['pairs']:
        if item['node']==node:acc=add(acc,multiply(hash_to_G1(bytes.fromhex(name)+item['index'].to_bytes(8,'big'),p.DST,hashlib.sha256),int(item['coefficient'])))
    for u,mu in zip(pub['generators'],proof['mu']):acc=add(acc,multiply(decompress_G1(int(u,16)),int(mu)))
    g=hash_to_G2(b'I12 fixed public generator v1',b'I12_SW08_BLS12381G2_XMD:SHA-256_SSWU_RO_V1',hashlib.sha256)
    raw=bytes.fromhex(pub['public_key']);pk=decompress_G2((int.from_bytes(raw[:48],'big'),int.from_bytes(raw[48:],'big')))
    independent=pairing(g,decompress_G1(int(proof['sigma'],16)))==pairing(pk,acc)
    expected=not bool({tuple(x) for x in first['fault']['blocks']}.intersection((node,x['index']) for x in challenge['pairs'] if x['node']==node))
    if independent!=expected:errors.append('independent pairing disagreement')
    p.save_json(artifact_out/'independent_pairing_check.json',dict(trial_id=first['trial_id'],node=node,implementation='py_ecc 8.0.0 vs pyblst 0.3.15',passed=independent==expected,pairing_equation_holds=independent,expected_node_valid=expected,description='actual preserved challenge/proof; independently reconstruct hash and group equation; not formal security proof'))
    versions=p.load_json(out/'code_version.json')
    with zipfile.ZipFile(artifact_out/'code_snapshot.zip','x',compression=zipfile.ZIP_DEFLATED) as z:
        for name,digest in versions.items():
            source=ROOT/'tools'/name
            if p.sha(source.read_bytes())!=digest:errors.append('followup source hash mismatch '+name)
            z.write(source,name)
    p.save_json(artifact_out/'verification_report.json',dict(started_at=start,ended_at=p.stamp(),passed=not errors,proofs_reverified=count,unique_seeds=len(set(x['sampling_seed'] for x in rows.values())),independent_pairing_checked=True,summary_cells=len(intervals),errors=errors))
    print(json.dumps(p.load_json(artifact_out/'verification_report.json')))
    return int(bool(errors))
if __name__=='__main__':sys.exit(main(sys.argv[1]))
