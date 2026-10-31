import bootstrap
import protocol as p
from pathlib import Path
import json,sys,random,time,csv,copy,itertools,traceback,platform,os,ctypes,shutil,zipfile,importlib.metadata as md
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parents[1]
CONFIG=p.load_json(ROOT/'tools/config.json')

def sampling_seed(*parts):
    return int(p.sha(p.wire(['I12-matrix-sampling-v2',*parts])),16)

def main():
    rid=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    inp=ROOT/'I12-INPUT/数据'/rid; res=ROOT/'I12-RESULTS/数据'/rid
    inp.mkdir(parents=True,exist_ok=False); res.mkdir(parents=True,exist_ok=False)
    p.save_json(inp/'config.json',CONFIG)
    files=[x for x in (ROOT/'tools').glob('*') if x.suffix in ['.py','.json']]
    p.save_json(res/'code_version.json',dict(files={x.name:p.sha(x.read_bytes()) for x in files},version='i12-sw08-1.1',git_commit=None))
    with zipfile.ZipFile(res/'code_snapshot.zip','x',compression=zipfile.ZIP_DEFLATED) as z:
        for file in files: z.write(file,file.name)
    started=p.stamp(); run=dict(run_id=rid,started_at=started,project=CONFIG['project'],status='running',scope=CONFIG['scope'])
    p.save_json(res/'run_started.json',run)
    class Memory(ctypes.Structure):
        _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(n,ctypes.c_ulonglong) for n in ['total','available','total_page','available_page','total_virtual','available_virtual','extended']]
    mem=Memory();mem.length=ctypes.sizeof(mem)
    if os.name == 'nt': ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
    p.save_json(res/'environment.json',dict(python=sys.version,executable=sys.executable,os=platform.platform(),processor=platform.processor(),logical_cpus=os.cpu_count(),ram_total=mem.total,ram_available=mem.available,disk_free=shutil.disk_usage(ROOT).free,timer=time.get_clock_info('perf_counter').__dict__,packages={x:md.version(x) for x in ['pyblst','reedsolo','py-ecc','cryptography','numpy','matplotlib']},command=[sys.executable,'-X','utf8',str(Path(__file__).resolve())],network='none; in-process sequential logical nodes; no artificial latency in performance runs',timestamp_source='host UTC clock; no backdating'))
    challenges=(inp/'challenges.jsonl').open('xb'); proofs=(res/'proofs.jsonl').open('xb'); events=(res/'events.jsonl').open('xb')
    raw=(res/'measurements.csv').open('x',encoding='utf-8-sig',newline=''); writer=None; setups=[]; catalog={}; row_count=0; trial_count=0; mismatches=[]
    def event(obj): events.write(p.wire(dict(at=p.stamp(),**obj))+b'\n'); events.flush()
    def execute(info,c,phase,case,sample_seed,expected=True,fault=None,transform=None,policy=None,source_info=None):
        nonlocal trial_count,row_count,writer
        trial_count+=1; tid=f'T{trial_count:06d}'; fault=fault or {}; bad={tuple(x) for x in fault.get('blocks',[])}
        hit=len(bad.intersection((x['node'],x['index']) for x in c['pairs']))
        record=dict(trial_id=tid,file_key=info['key'],phase=phase,case=case,sampling_seed=sample_seed,challenge=c,fault=fault)
        challenges.write(p.wire(record)+b'\n'); challenges.flush()
        methods=list(CONFIG['methods']); random.Random(trial_count+info['seed']).shuffle(methods)
        for method in methods:
            pub=info['pubs'][method]; directory=info['directory']; before=p.stamp(); t0=time.perf_counter_ns()
            if source_info:
                source_pub=source_info['pubs'][method]; source_c=copy.deepcopy(c);source_c['file_id']=source_pub['file_id']
                response,reads=p.prove(source_info['directory'],source_pub,source_c,method)
                response['file_id']=pub['file_id'];response['challenge_id']=p.sha(p.wire(c))
            else: response,reads=p.prove(directory,pub,c,method,fault)
            generation_ns=time.perf_counter_ns()-t0
            if transform: response=transform(response,method,pub,c)
            t=time.perf_counter_ns(); encoded=p.wire(response); serialization_ns=time.perf_counter_ns()-t
            t=time.perf_counter_ns()
            if policy:
                session=p.SessionVerifier(pub,pub['signing_public'])
                if policy=='replay':
                    first=session.verify(c,json.loads(encoded),method)
                    accepted,reason=session.verify(c,json.loads(encoded),method)
                elif policy=='timeout': accepted,reason=session.verify(c,json.loads(encoded),method,elapsed_ms=2,timeout_ms=1)
            else: accepted,reason=p.verify(pub,pub['signing_public'],c,json.loads(encoded),method)
            verify_ns=time.perf_counter_ns()-t
            expect=expected[method] if isinstance(expected,dict) else expected
            row=dict(trial_id=tid,phase=phase,case=case,method=method,file_key=info['key'],seed=info['seed'],size_bytes=info['size'],nodes=info['nodes'],q=len(c['pairs']),population=len(p.universe(pub)),damaged=len(bad),damage_fraction=len(bad)/len(p.universe(pub)),challenged_damaged=hit,sampling_seed=sample_seed,accepted=int(accepted),expected_accepted=int(expect),expectation_match=int(accepted==expect),reason=reason,proof_generation_ns=generation_ns,proof_serialization_ns=serialization_ns,verification_ns=verify_ns,challenge_wire_bytes=len(p.wire(c)),proof_wire_bytes=len(encoded),total_wire_bytes=len(p.wire(c))+len(encoded),storage_read_bytes=reads,contacted_nodes=len({x['node'] for x in c['pairs']}),client_metadata_bytes=len(p.wire(pub)),started_at=before,ended_at=p.stamp())
            if writer is None: writer=csv.DictWriter(raw,fieldnames=list(row));writer.writeheader()
            writer.writerow(row);raw.flush();row_count+=1
            proofs.write(p.wire(dict(trial_id=tid,method=method,response=response,accepted=accepted,reason=reason,policy=policy))+b'\n');proofs.flush()
            if accepted!=expect: mismatches.append(dict(trial_id=tid,method=method,case=case,reason=reason));event(dict(kind='unexpected_result',row=row))
    try:
        matrix=list(itertools.product(CONFIG['independent_seeds'],CONFIG['sizes_bytes'],CONFIG['nodes']))
        random.Random(2023090800).shuffle(matrix)
        p.save_json(inp/'matrix_order.json',[dict(seed=a,size_bytes=b,nodes=c) for a,b,c in matrix])
        for seed,size,n in matrix:
            key=f'S{seed}_B{size}_N{n}'; directory=inp/'files'/key
            event(dict(kind='setup_start',file_key=key)); pub=p.setup(directory,size,n,seed,CONFIG['sectors_per_block'],CONFIG['data_shards'])
            info=dict(key=key,directory=directory,pubs={'sw':pub,'ed25519':p.load_json(directory/'public_ed25519.json')},size=size,nodes=n,seed=seed)
            catalog[(seed,size,n)]=info
            gen=p.load_json(directory/'generation.json'); keep=random.Random(seed+n).sample(range(n),CONFIG['data_shards'])
            t=time.perf_counter_ns(); recovered=p.reconstruct(directory,pub,keep); recovery_ns=time.perf_counter_ns()-t
            setup=dict(file_key=key,size_bytes=size,nodes=n,input_relative=directory.relative_to(inp).as_posix(),blocks=len(p.universe(pub)),recovery_keep=keep,recovery_success=recovered,recovery_ns=recovery_ns,**gen)
            setups.append(setup);event(dict(kind='setup_complete',**setup))
            for q in CONFIG['challenge_counts']:
                for repeat in range(CONFIG['warmups_per_cell']+CONFIG['measured_repeats_per_cell']):
                    ss=sampling_seed('performance',seed,size,n,q,repeat)
                    c=p.challenge(pub,q,ss);phase='warmup' if repeat<CONFIG['warmups_per_cell'] else 'performance'
                    execute(info,c,phase,'intact',ss)
            print('completed normal',key,'rows',row_count,flush=True)
        p.save_json(inp/'file_catalog.json',setups)
        for seed in CONFIG['independent_seeds']:
            info=catalog[(seed,CONFIG['fault_file_bytes'],CONFIG['fault_nodes'])];pub=info['pubs']['sw']; population=p.universe(pub)
            for fraction in CONFIG['fault_fractions']:
                damaged=max(1,int(len(population)*fraction)); fault_seed=sampling_seed('fault-set',seed,fraction)
                bad=random.Random(fault_seed).sample(population,damaged)
                for q in CONFIG['challenge_counts']:
                    for kind in CONFIG['fault_kinds']:
                        for repeat in range(CONFIG['fault_repeats_per_seed']):
                            ss=sampling_seed('fault-query',seed,fraction,q,repeat)
                            c=p.challenge(pub,q,ss); hit=bool(set(bad).intersection((x['node'],x['index']) for x in c['pairs']))
                            execute(info,c,'fault',kind,ss,expected=not hit,fault=dict(kind=kind,blocks=bad,requested_fraction=fraction,fault_seed=fault_seed))
            # Same query supports adversarial protocol cases independent from fault sampling.
            q=16; ss=seed+999999; c=p.challenge(pub,q,ss)
            def tamper(response,method,pub,c):
                r=copy.deepcopy(response)
                if method=='sw': r['nodes'][0]['mu'][0]=str((int(r['nodes'][0]['mu'][0])+1)%p.R)
                else:
                    block=bytes.fromhex(r['nodes'][0]['records'][0]['data']);r['nodes'][0]['records'][0]['data']=(bytes([block[0]^1])+block[1:]).hex()
                return r
            execute(info,c,'adversarial','proof_tamper',ss,False,transform=tamper)
            execute(info,c,'adversarial','replay_consumed_session',ss,False,policy='replay')
            execute(info,c,'policy_simulation','timeout_2ms_over_1ms',ss,False,policy='timeout')
            other_seed=next(x for x in CONFIG['independent_seeds'] if x!=seed)
            other=catalog[(other_seed,CONFIG['fault_file_bytes'],CONFIG['fault_nodes'])]
            execute(info,c,'adversarial','wrong_file_relabelled',ss,False,source_info=other)
            def substitute(r,method,pub,c):
                r=copy.deepcopy(r);r['nodes'][0],r['nodes'][1]=r['nodes'][1],r['nodes'][0]
                r['nodes'][0]['node'],r['nodes'][1]['node']=r['nodes'][1]['node'],r['nodes'][0]['node'];return r
            execute(info,c,'adversarial','wrong_shard_relabelled',ss,False,transform=substitute)
            old={method:p.prove(info['directory'],info['pubs'][method],c,method)[0] for method in CONFIG['methods']}
            fresh=p.challenge(pub,q,indices=[(x['node'],x['index']) for x in c['pairs']])
            p.save_json(inp/f'replay_source_{seed}.json',dict(challenge=c,responses=old))
            def replay_new(_,method,pub,c):
                r=copy.deepcopy(old[method]);r['challenge_id']=p.sha(p.wire(c));return r
            execute(info,fresh,'adversarial','replay_new_coefficients_relabelled',ss,{'sw':False,'ed25519':True},transform=replay_new)
            print('completed faults',seed,'rows',row_count,flush=True)
        status='complete' if not mismatches else 'complete_with_unexpected_results'
    except Exception:
        status='failed';event(dict(kind='fatal_exception',traceback=traceback.format_exc()));raise
    finally:
        for f in [challenges,proofs,events,raw]: f.close()
        p.save_json(res/'run_finished.json',dict(**{key:value for key,value in run.items() if key!='status'},ended_at=p.stamp(),status=locals().get('status','failed'),measurement_rows=row_count,challenges=trial_count,unexpected_results=mismatches))
        print('RUN_ID',rid,'STATUS',locals().get('status'),'ROWS',row_count,flush=True)

if __name__=='__main__': main()
