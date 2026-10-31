"""Declared follow-up: every 3 damage levels × 3 q × 3 source setups × 100 audits.
Original observations remain intact. Only SW corruption audits; no time-performance claim.
"""
import bootstrap
import protocol as p
from pathlib import Path
import sys,csv,json,random,time,math,collections
ROOT=Path(__file__).resolve().parents[1]
def main(rid):
    parent_in=ROOT/'I12-INPUT/数据'/rid;parent_out=ROOT/'I12-RESULTS/数据'/rid
    inp=parent_in/'sampling_followup';out=parent_out/'sampling_followup';inp.mkdir(exist_ok=False);out.mkdir(exist_ok=False)
    started=p.stamp(); cfg=p.load_json(parent_in/'config.json')
    prereg=dict(started_at=started,parent_run_id=rid,reason='Original additive sample seeds overlap between source setups; one detection cell deviates upward. Preserve all original observations.',matrix='3 damage levels x 3 q x 3 setups x 100 draws = 2700 actual SW corruption proofs',seed_derivation='SHA256(UTF8 compact JSON [I12-confirm-v1, source_seed, damaged, q, repeat]) interpreted as integer',planned_audits=2700,selection='all nine cells, not only the deviating cell')
    p.save_json(inp/'preregistered.json',prereg);p.save_json(out/'code_version.json',{x.name:p.sha(x.read_bytes()) for x in [ROOT/'tools/protocol.py',Path(__file__)]})
    qfile=(inp/'challenges.jsonl').open('xb');pfile=(out/'proofs.jsonl').open('xb');f=(out/'measurements.csv').open('x',encoding='utf-8-sig',newline='');w=None;trial=0;seeds=set();mismatches=[]
    for seed in cfg['independent_seeds']:
        key=f'S{seed}_B65536_N6';directory=parent_in/'files'/key;pub=p.load_json(directory/'public.json');pop=p.universe(pub)
        for fraction in cfg['fault_fractions']:
            D=max(1,int(len(pop)*fraction));bad=random.Random(seed+int(fraction*10000)).sample(pop,D)
            for q in cfg['challenge_counts']:
                for repeat in range(100):
                    trial+=1;tid=f'C{trial:06d}';ss=int(p.sha(p.wire(['I12-confirm-v1',seed,D,q,repeat])),16)
                    if ss in seeds:raise ValueError('derived seed collision')
                    seeds.add(ss);c=p.challenge(pub,q,ss);fault=dict(kind='corrupt',blocks=bad)
                    hit=bool(set(bad).intersection((x['node'],x['index']) for x in c['pairs']))
                    qfile.write(p.wire(dict(trial_id=tid,file_key=key,source_seed=seed,sampling_seed=str(ss),challenge=c,fault=fault))+b'\n')
                    start=p.stamp();t=time.perf_counter_ns();response,reads=p.prove(directory,pub,c,'sw',fault);generation=time.perf_counter_ns()-t
                    t=time.perf_counter_ns();accepted,reason=p.verify(pub,pub['signing_public'],c,response);verify=time.perf_counter_ns()-t
                    row=dict(trial_id=tid,seed=seed,file_key=key,N=len(pop),D=D,q=q,repeat=repeat,sampling_seed=str(ss),detected=int(not accepted),expected_detected=int(hit),accepted=int(accepted),reason=reason,proof_generation_ns=generation,verification_ns=verify,challenge_wire_bytes=len(p.wire(c)),proof_wire_bytes=len(p.wire(response)),started_at=start,ended_at=p.stamp())
                    if w is None:w=csv.DictWriter(f,fieldnames=list(row));w.writeheader()
                    w.writerow(row);pfile.write(p.wire(dict(trial_id=tid,response=response,accepted=accepted,reason=reason))+b'\n')
                    if accepted==hit:mismatches.append(tid)
                qfile.flush();pfile.flush();f.flush();print('sampling check',seed,D,q,'audits',trial,flush=True)
    for file in [qfile,pfile,f]:file.close()
    rows=list(csv.DictReader((out/'measurements.csv').open(encoding='utf-8-sig')));groups=collections.defaultdict(list)
    for r in rows:groups[(int(r['D']),int(r['q']))].append(r)
    summary=[]
    for (D,q),items in sorted(groups.items()):
        N=int(items[0]['N']);k=sum(int(x['detected']) for x in items);theory=1-(math.comb(N-D,q)/math.comb(N,q) if q<=N-D else 0)
        summary.append(dict(N=N,D=D,q=q,n=len(items),detected=k,rate=k/len(items),theory=theory,rate_minus_theory=k/len(items)-theory))
    with (out/'detection_summary.csv').open('x',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(summary[0]));w.writeheader();w.writerows(summary)
    p.save_json(out/'run_finished.json',dict(started_at=started,ended_at=p.stamp(),status='complete' if not mismatches else 'complete_with_unexpected_results',audits=trial,unique_sampling_seeds=len(seeds),mismatches=mismatches))
    print('FOLLOWUP COMPLETE',trial,flush=True)
if __name__=='__main__':main(sys.argv[1])
