"""SW08 §3.3 public homomorphic authenticator, instantiated on BLS12-381.

Local research implementation, not a production or formally verified system.
The verifier receives only pinned public material, never storage paths/secret keys.
"""
import bootstrap
from pathlib import Path
import hashlib, json, secrets, random, time, math
from pyblst import BlstP1Element as P1, BlstP2Element as P2, miller_loop, final_verify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from reedsolo import RSCodec

R=int('73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001',16)
DST=b'I12_SW08_BLS12381G1_XMD:SHA-256_SSWU_RO_V1'
G2=P2.hash_to_group(b'I12 fixed public generator v1',b'I12_SW08_BLS12381G2_XMD:SHA-256_SSWU_RO_V1')
SECTOR_BYTES=31

def wire(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
def sha(data): return hashlib.sha256(data).hexdigest()
def scalar(): return secrets.randbelow(R-1)+1
def stamp():
    from datetime import datetime,timezone
    return datetime.now(timezone.utc).isoformat()
def save_json(path,obj):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f: f.write(wire(obj)+b'\n')
def load_json(path): return json.loads(Path(path).read_text(encoding='utf-8'))
def h(name,i): return P1.hash_to_group(bytes.fromhex(name)+i.to_bytes(8,'big'),DST)
def numbers(block,s):
    if len(block)!=s*SECTOR_BYTES: raise ValueError('invalid block length')
    return [int.from_bytes(block[j*31:(j+1)*31],'big') for j in range(s)]
def sign_message(name,i,block): return b'I12-ED-BLOCK-V1'+bytes.fromhex(name)+i.to_bytes(8,'big')+block

def rs_encode(data,k,n):
    """Systematic RS(n,k) over GF(256), across distinct node shards per stripe."""
    codec=RSCodec(n-k,nsize=n)
    padded=data+b'\0'*((-len(data))%k)
    shards=[bytearray() for _ in range(n)]
    for offset in range(0,len(padded),k):
        code=codec.encode(padded[offset:offset+k])
        for j,x in enumerate(code): shards[j].append(x)
    return list(map(bytes,shards))

def rs_decode(shards,k,n,original_length):
    missing=[i for i in range(n) if i not in shards]
    if len(missing)>n-k: raise ValueError('not enough shards')
    lengths={len(x) for x in shards.values()}
    if len(lengths)!=1: raise ValueError('unequal shard lengths')
    codec=RSCodec(n-k,nsize=n); out=bytearray()
    for pos in range(next(iter(lengths))):
        code=bytes(shards[i][pos] if i in shards else 0 for i in range(n))
        decoded,_,_=codec.decode(code,erase_pos=missing,only_erasures=True)
        out.extend(decoded)
    return bytes(out[:original_length])

def setup(directory,size,n,seed,s=8,k=4):
    """fresh synthetic file + fresh encryption/signing keys for every independent setup."""
    directory=Path(directory); directory.mkdir(parents=True,exist_ok=False)
    started=stamp(); t0=time.perf_counter_ns()
    plaintext=random.Random(seed).randbytes(size)
    (directory/'payload.bin').write_bytes(plaintext)
    file_id=secrets.token_hex(32); key=AESGCM.generate_key(bit_length=256); nonce=secrets.token_bytes(12)
    aad=wire(dict(file_id=file_id,plaintext_bytes=size,schema='I12-v1'))
    t=time.perf_counter_ns(); ciphertext=AESGCM(key).encrypt(nonce,plaintext,aad); encryption_ns=time.perf_counter_ns()-t
    t=time.perf_counter_ns(); shards=rs_encode(ciphertext,k,n); encoding_ns=time.perf_counter_ns()-t
    signing=Ed25519PrivateKey.generate(); alpha=scalar(); pk=G2.scalar_mul(alpha)
    u=[P1.hash_to_group(secrets.token_bytes(32),DST) for _ in range(s)]
    pub=dict(schema='I12-SW08-public-v1',file_id=file_id,nodes=n,k=k,sectors=s,sector_bytes=31,
             plaintext_bytes=size,ciphertext_bytes=len(ciphertext),shard_bytes=len(shards[0]),
             public_key=pk.compress().hex(),signing_public=signing.public_key().public_bytes_raw().hex(),
             generators=[x.compress().hex() for x in u],nonce=nonce.hex(),aad=aad.hex(),
             block_bytes=s*31,node_tags=[],plaintext_sha256=sha(plaintext),ciphertext_sha256=sha(ciphertext))
    sw_tag_ns=0; baseline_tag_ns=0; io_ns=0; allocation=[]
    for node,shard in enumerate(shards):
        ndir=directory/'nodes'/f'node-{node:02d}'; ndir.mkdir(parents=True)
        padded=shard+b'\0'*((-len(shard))%(s*31)); blocks=len(padded)//(s*31)
        name=secrets.token_hex(32)
        descriptor=dict(file_id=file_id,node=node,name=name,blocks=blocks,sectors=s,
                        generators=pub['generators'],public_key=pub['public_key'],layout=dict(k=k,n=n,shard_bytes=len(shard)))
        signature=signing.sign(wire(descriptor)).hex()
        pub['node_tags'].append(dict(descriptor=descriptor,signature=signature))
        sw_tags=[]; ed_tags=[]
        for i in range(blocks):
            block=padded[i*s*31:(i+1)*s*31]
            t=time.perf_counter_ns(); acc=h(name,i)
            for uj,mij in zip(u,numbers(block,s)): acc=acc+uj.scalar_mul(mij)
            tag=acc.scalar_mul(alpha).compress(); sw_tag_ns+=time.perf_counter_ns()-t
            t=time.perf_counter_ns(); ed=signing.sign(sign_message(name,i,block)); baseline_tag_ns+=time.perf_counter_ns()-t
            t=time.perf_counter_ns(); rel=f'nodes/node-{node:02d}/block-{i:06d}.bin'; (directory/rel).write_bytes(block); io_ns+=time.perf_counter_ns()-t
            allocation.append(dict(node=node,block=i,path=rel,bytes=len(block),sha256=sha(block),
                                   shard_offset=i*s*31,valid_shard_bytes=max(0,min(s*31,len(shard)-i*s*31))))
            sw_tags.append(tag); ed_tags.append(ed)
        (ndir/'sw_tags.bin').write_bytes(b''.join(sw_tags)); (ndir/'ed_tags.bin').write_bytes(b''.join(ed_tags))
    baseline={key:value for key,value in pub.items() if key not in ['public_key','generators','node_tags']}
    baseline['schema']='I12-Ed25519-sampling-v1'; baseline['node_tags']=[]
    for tag in pub['node_tags']:
        descriptor={key:value for key,value in tag['descriptor'].items() if key not in ['generators','public_key']}
        baseline['node_tags'].append(dict(descriptor=descriptor,signature=signing.sign(wire(descriptor)).hex()))
    baseline['manifest_signature']=signing.sign(wire(baseline)).hex()
    save_json(directory/'public_ed25519.json',baseline)
    # A top-level signed manifest binds encryption, coding, and node allocation parameters.
    pub['manifest_signature']=signing.sign(wire(pub)).hex()
    save_json(directory/'public.json',pub)
    save_json(directory/'allocation.json',allocation)
    save_json(directory/'test_only_secrets.json',dict(not_for_production=True,publication='synthetic test vectors; released after experiments',
              aes_key=key.hex(),alpha=str(alpha),ed25519_private=signing.private_bytes_raw().hex()))
    save_json(directory/'generation.json',dict(seed=seed,generator='Python random.Random(seed).randbytes(size)',
             crypto_randomness='OS CSPRNG through secrets/AESGCM/Ed25519; not derived from seed',started_at=started,ended_at=stamp(),
             encryption_ns=encryption_ns,rs_encoding_ns=encoding_ns,sw_tag_ns=sw_tag_ns,ed_tag_ns=baseline_tag_ns,
             block_write_ns=io_ns,total_setup_ns=time.perf_counter_ns()-t0))
    return pub

def validate_public(pub,pinned,need_sw=True):
    if pub['signing_public']!=pinned: raise ValueError('untrusted signing key')
    spk=Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned)); raw=dict(pub); sig=raw.pop('manifest_signature')
    spk.verify(bytes.fromhex(sig),wire(raw))
    pk=None; us=[]
    if need_sw:
        pk=P2.uncompress(bytes.fromhex(pub['public_key']))
        if pk==P2(): raise ValueError('identity public key')
        us=[P1.uncompress(bytes.fromhex(x)) for x in pub['generators']]
        if len(us)!=pub['sectors'] or any(x==P1() for x in us): raise ValueError('bad generators')
    for node,tag in enumerate(pub['node_tags']):
        spk.verify(bytes.fromhex(tag['signature']),wire(tag['descriptor']))
        d=tag['descriptor']
        if d['node']!=node or d['file_id']!=pub['file_id']: raise ValueError('inconsistent node tag')
        if need_sw and (d['public_key']!=pub['public_key'] or d['generators']!=pub['generators']): raise ValueError('inconsistent SW tag')
    return pk,us,spk

def universe(pub): return [(j,i) for j,t in enumerate(pub['node_tags']) for i in range(t['descriptor']['blocks'])]

def challenge(pub,q,seed=None,indices=None):
    population=universe(pub)
    chosen=indices if indices is not None else (random.Random(seed) if seed is not None else secrets.SystemRandom()).sample(population,q)
    pairs=[dict(node=node,index=i,coefficient=str(scalar())) for node,i in sorted(chosen)]
    return dict(schema='I12-challenge-v1',file_id=pub['file_id'],nonce=secrets.token_hex(32),pairs=pairs)

def validate_challenge(pub,c):
    if c['schema']!='I12-challenge-v1' or c['file_id']!=pub['file_id'] or len(bytes.fromhex(c['nonce']))!=32: raise ValueError('challenge context')
    seen=set()
    if not c['pairs']: raise ValueError('empty challenge')
    for p in c['pairs']:
        j,i=p['node'],p['index']; v=int(p['coefficient'])
        if type(j)!=int or type(i)!=int or not(0<=j<pub['nodes']) or not(0<=i<pub['node_tags'][j]['descriptor']['blocks']) or not(0<v<R): raise ValueError('challenge range')
        if (j,i) in seen: raise ValueError('duplicate index')
        seen.add((j,i))

def prove(directory,pub,c,method='sw',fault=None):
    """Sequential local logical-node service; reads blocks, never plaintext/keys.
    Missing/corrupt view is an explicit injected storage fault; originals untouched.
    """
    validate_challenge(pub,c); fault=fault or {}; bad={tuple(x) for x in fault.get('blocks',[])}
    grouped={}
    for item in c['pairs']: grouped.setdefault(item['node'],[]).append(item)
    proofs=[]; reads=0
    for node,pairs in sorted(grouped.items()):
        ndir=Path(directory)/'nodes'/f'node-{node:02d}'
        sigma=P1(); mu=[0]*pub['sectors']; records=[]; missing=False
        with (ndir/('sw_tags.bin' if method=='sw' else 'ed_tags.bin')).open('rb') as tagfile:
            for item in pairs:
                i=item['index']; v=int(item['coefficient']); key=(node,i)
                if key in bad and fault.get('kind')=='missing': missing=True; break
                try: block=(ndir/f'block-{i:06d}.bin').read_bytes()
                except FileNotFoundError: missing=True; break
                reads+=len(block)
                if key in bad and fault.get('kind')=='corrupt': block=bytes([block[0]^1])+block[1:]
                width=48 if method=='sw' else 64; tagfile.seek(i*width); tag=tagfile.read(width); reads+=len(tag)
                if method=='sw':
                    sigma=sigma+P1.uncompress(tag).scalar_mul(v)
                    for j,value in enumerate(numbers(block,pub['sectors'])): mu[j]=(mu[j]+v*value)%R
                else: records.append(dict(index=i,data=block.hex(),signature=tag.hex()))
        if missing: proofs.append(dict(node=node,status='missing')); continue
        proofs.append(dict(node=node,status='ok',sigma=sigma.compress().hex(),mu=[str(x) for x in mu]) if method=='sw' else dict(node=node,status='ok',records=records))
    return dict(method=method,challenge_id=sha(wire(c)),file_id=pub['file_id'],nodes=proofs),reads

def verify(pub,pinned,c,response,method='sw'):
    try:
        validate_challenge(pub,c); pk,us,spk=validate_public(pub,pinned,need_sw=method=='sw')
        if response['method']!=method or response['challenge_id']!=sha(wire(c)) or response['file_id']!=pub['file_id']: return False,'context_mismatch'
        groups={}
        for item in c['pairs']: groups.setdefault(item['node'],[]).append(item)
        if [p['node'] for p in response['nodes']]!=sorted(groups): return False,'node_set_mismatch'
        for proof in response['nodes']:
            if proof['status']!='ok': return False,'missing_response'
            node=proof['node']; name=pub['node_tags'][node]['descriptor']['name']; pairs=groups[node]
            if method=='sw':
                sigma=P1.uncompress(bytes.fromhex(proof['sigma'])); mu=[int(x) for x in proof['mu']]
                if len(mu)!=len(us) or any(x<0 or x>=R for x in mu): return False,'noncanonical_scalar'
                acc=P1()
                for p in pairs: acc=acc+h(name,p['index']).scalar_mul(int(p['coefficient']))
                for u,value in zip(us,mu): acc=acc+u.scalar_mul(value)
                if not final_verify(miller_loop(sigma,G2),miller_loop(acc,pk)): return False,'pairing_mismatch'
            else:
                if [r['index'] for r in proof['records']]!=[p['index'] for p in pairs]: return False,'indices_mismatch'
                for rec in proof['records']:
                    block=bytes.fromhex(rec['data'])
                    if len(block)!=pub['block_bytes']: return False,'block_size'
                    spk.verify(bytes.fromhex(rec['signature']),sign_message(name,rec['index'],block))
        return True,'valid'
    except (ValueError,KeyError,TypeError,IndexError,OverflowError,InvalidSignature): return False,'malformed_or_bad_signature'

class SessionVerifier:
    """Experiment session layer; not a claim that SW itself requires persistent state."""
    def __init__(self,pub,pinned): self.pub,self.pinned,self.used=pub,pinned,set()
    def verify(self,c,p,method='sw',elapsed_ms=0,timeout_ms=None):
        cid=sha(wire(c))
        if cid in self.used: return False,'replay_consumed_session'
        self.used.add(cid)
        if timeout_ms is not None and elapsed_ms>timeout_ms: return False,'timeout_policy'
        return verify(self.pub,self.pinned,c,p,method)

def reconstruct(directory,pub,keep):
    shards={node:b''.join((Path(directory)/'nodes'/f'node-{node:02d}'/f'block-{i:06d}.bin').read_bytes() for i in range(pub['node_tags'][node]['descriptor']['blocks']))[:pub['shard_bytes']] for node in keep}
    ct=rs_decode(shards,pub['k'],pub['nodes'],pub['ciphertext_bytes'])
    secrets_data=load_json(Path(directory)/'test_only_secrets.json')
    plain=AESGCM(bytes.fromhex(secrets_data['aes_key'])).decrypt(bytes.fromhex(pub['nonce']),ct,bytes.fromhex(pub['aad']))
    return sha(plain)==pub['plaintext_sha256']
