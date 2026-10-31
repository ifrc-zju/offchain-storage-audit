import bootstrap
from pathlib import Path
import csv,json,collections,statistics,math,sys
import protocol as p
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[1]

def csvwrite(path,rows):
    if not rows: return
    with path.open('x',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def wilson(k,n):
    z=1.95996398454; ph=k/n; den=1+z*z/n; center=(ph+z*z/(2*n))/den; half=z*math.sqrt(ph*(1-ph)/n+z*z/(4*n*n))/den
    return center-half,center+half
def probability(N,D,q): return 1-(math.comb(N-D,q)/math.comb(N,q) if q<=N-D else 0)
def main(rid):
    data=ROOT/'I12-RESULTS/数据'/rid; out=data/'analysis'; out.mkdir(exist_ok=False)
    rows=list(csv.DictReader((data/'measurements.csv').open(encoding='utf-8-sig')))
    groups=collections.defaultdict(list)
    for row in rows:
        if row['phase']=='performance':groups[tuple(row[k] for k in ['method','size_bytes','nodes','q'])].append(row)
    summaries=[]; seeds=[]
    for (method,size,nodes,q),items in sorted(groups.items()):
        d=dict(method=method,size_bytes=int(size),nodes=int(nodes),q=int(q),n_trials=len(items),independent_setups=len(set(x['seed'] for x in items)),accepted=sum(int(x['accepted']) for x in items))
        for field in ['proof_generation_ns','verification_ns','proof_serialization_ns','proof_wire_bytes','challenge_wire_bytes','total_wire_bytes','client_metadata_bytes']:
            values=[float(x[field]) for x in items]
            d[field+'_mean']=statistics.mean(values);d[field+'_std']=statistics.stdev(values);d[field+'_median']=statistics.median(values)
            d[field+'_min']=min(values);d[field+'_max']=max(values)
        summaries.append(d)
        for seed in sorted({x['seed'] for x in items}):
            sub=[x for x in items if x['seed']==seed]
            seeds.append(dict(method=method,size_bytes=int(size),nodes=int(nodes),q=int(q),seed=int(seed),n=len(sub),proof_ms_mean=statistics.mean(int(x['proof_generation_ns'])/1e6 for x in sub),verify_ms_mean=statistics.mean(int(x['verification_ns'])/1e6 for x in sub)))
    csvwrite(out/'performance_summary.csv',summaries);csvwrite(out/'performance_by_seed.csv',seeds)
    faultgroups=collections.defaultdict(list)
    for row in rows:
        if row['phase']=='fault':faultgroups[tuple(row[k] for k in ['method','case','population','damaged','q'])].append(row)
    faultsummary=[]; byseed=[]
    for (method,kind,N,D,q),items in sorted(faultgroups.items()):
        N,D,q=map(int,[N,D,q]);detected=sum(1-int(x['accepted']) for x in items); rates=[]
        for seed in sorted({x['seed'] for x in items}):
            sub=[x for x in items if x['seed']==seed];k=sum(1-int(x['accepted']) for x in sub);lo,hi=wilson(k,len(sub));rates.append(k/len(sub))
            byseed.append(dict(method=method,case=kind,population=N,damaged=D,q=q,seed=int(seed),n=len(sub),detected=k,rate=k/len(sub),wilson95_low=lo,wilson95_high=hi,theory=probability(N,D,q)))
        faultsummary.append(dict(method=method,case=kind,population=N,damaged=D,damage_fraction=D/N,q=q,n=len(items),independent_fault_sets=len(rates),detected=detected,rate=detected/len(items),theory=probability(N,D,q),rate_minus_theory=detected/len(items)-probability(N,D,q),seed_rate_std=statistics.stdev(rates),sampled_hit_count=sum(int(x['challenged_damaged'])>0 for x in items),unexpected=sum(1-int(x['expectation_match']) for x in items)))
    csvwrite(out/'detection_summary.csv',faultsummary);csvwrite(out/'detection_by_seed.csv',byseed)
    casegroups=collections.defaultdict(list)
    for r in rows: casegroups[(r['phase'],r['case'],r['method'])].append(r)
    cases=[dict(phase=a,case=b,method=c,trials=len(v),accepted=sum(int(r['accepted']) for r in v),unexpected=sum(1-int(r['expectation_match']) for r in v)) for (a,b,c),v in sorted(casegroups.items())]
    csvwrite(out/'case_summary.csv',cases)
    # Display medians and variability; no fitted target curves or fabricated records.
    fig,axes=plt.subplots(1,3,figsize=(13,3.8),layout='constrained')
    for method,color in [('sw','#356CB6'),('ed25519','#C77432')]:
        subset=sorted([r for r in summaries if r['method']==method and r['size_bytes']==1048576 and r['nodes']==6],key=lambda r:r['q'])
        for ax,field,label,scale in [(axes[0],'proof_generation_ns','Proof generation (ms)',1e6),(axes[1],'verification_ns','Verification (ms)',1e6),(axes[2],'total_wire_bytes','Challenge + proof (KiB)',1024)]:
            ax.plot([r['q'] for r in subset],[r[field+'_median']/scale for r in subset],marker='o',label=method,color=color)
            ax.set_xlabel('Sampled blocks (q)');ax.set_ylabel(label);ax.set_xticks([4,16,64]);ax.grid(alpha=.2)
    axes[0].legend();fig.suptitle('Measured local experiment: 1 MiB, 6 logical nodes (median of 15 trials)')
    fig.savefig(out/'performance.png',dpi=180);fig.savefig(out/'performance.svg');plt.close(fig)
    fig,ax=plt.subplots(figsize=(7.8,4.5),layout='constrained')
    for D,color in [(1,'#356CB6'),(5,'#C77432'),(20,'#36866D')]:
        subset=sorted([r for r in faultsummary if r['method']=='sw' and r['case']=='corrupt' and r['damaged']==D],key=lambda r:r['q'])
        if not subset:continue
        ax.plot([r['q'] for r in subset],[r['rate'] for r in subset],marker='o',color=color,label=f'measured D={D}/{subset[0]["population"]}')
        ax.plot([r['q'] for r in subset],[r['theory'] for r in subset],linestyle='--',color=color,label=f'hypergeometric D={D}')
    ax.set(xlabel='Sampled blocks (q)',ylabel='Detection rate',ylim=(-.03,1.06),xticks=[4,16,64],title='Ciphertext corruption: observed detections and sampling theory')
    ax.grid(alpha=.2);ax.legend(ncol=2,fontsize=9);fig.savefig(out/'detection.png',dpi=180);fig.savefig(out/'detection.svg');plt.close(fig)
    p.save_json(out/'analysis_checks.json',dict(raw_rows=len(rows),phase_counts=dict(collections.Counter(r['phase'] for r in rows)),performance_groups=len(summaries),unexpected=sum(1-int(r['expectation_match']) for r in rows),notes='Warmups excluded. Performance repeats clustered by setup seed. Fault aggregate is descriptive; per-seed Wilson intervals assume independent audit draws on fixed fault set. Same-index challenges across methods and fault kinds are paired, never pooled as independent trials.'))
    print(json.dumps(p.load_json(out/'analysis_checks.json'),ensure_ascii=False))
if __name__=='__main__': main(sys.argv[1])
