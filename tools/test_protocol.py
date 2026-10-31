import bootstrap
import unittest, tempfile, shutil, copy, itertools, hashlib, time
from pathlib import Path
import protocol as p

class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='i12-test-')
        cls.directory=Path(cls.tmp.name)/'case'
        cls.pub=p.setup(cls.directory,1025,6,20230908,s=4)
        cls.pin=cls.pub['signing_public']; cls.c=p.challenge(cls.pub,6,1234)
        cls.proof,_=p.prove(cls.directory,cls.pub,cls.c)
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def test_normal_public_verification(self):
        self.assertEqual(p.verify(self.pub,self.pin,self.c,self.proof),(True,'valid'))
    def test_actual_missing_file(self):
        item=self.c['pairs'][0]; file=self.directory/'nodes'/f"node-{item['node']:02d}"/f"block-{item['index']:06d}.bin"
        raw=file.read_bytes(); file.unlink()
        try:
            proof,_=p.prove(self.directory,self.pub,self.c)
            self.assertFalse(p.verify(self.pub,self.pin,self.c,proof)[0])
        finally: file.write_bytes(raw)
    def test_fault_detection_matches_queried_blocks(self):
        chosen={(x['node'],x['index']) for x in self.c['pairs']}; hit=next(iter(chosen)); miss=next(x for x in p.universe(self.pub) if x not in chosen)
        for kind in ['missing','corrupt']:
            for block,expected in [(hit,False),(miss,True)]:
                proof,_=p.prove(self.directory,self.pub,self.c,fault={'kind':kind,'blocks':[block]})
                self.assertEqual(p.verify(self.pub,self.pin,self.c,proof)[0],expected)
    def test_bad_proof_wrong_file_and_node(self):
        bad=copy.deepcopy(self.proof); bad['nodes'][0]['mu'][0]=str((int(bad['nodes'][0]['mu'][0])+1)%p.R)
        self.assertFalse(p.verify(self.pub,self.pin,self.c,bad)[0])
        bad=copy.deepcopy(self.proof); bad['file_id']='00'*32
        self.assertFalse(p.verify(self.pub,self.pin,self.c,bad)[0])
        bad=copy.deepcopy(self.proof); bad['nodes'][0]['node']=99
        self.assertFalse(p.verify(self.pub,self.pin,self.c,bad)[0])
    def test_replay_with_new_coefficients_and_relabelled_envelope(self):
        c=p.challenge(self.pub,len(self.c['pairs']),indices=[(x['node'],x['index']) for x in self.c['pairs']])
        bad=copy.deepcopy(self.proof); bad['challenge_id']=p.sha(p.wire(c))
        self.assertFalse(p.verify(self.pub,self.pin,c,bad)[0])
        v=p.SessionVerifier(self.pub,self.pin)
        self.assertTrue(v.verify(self.c,self.proof)[0]); self.assertFalse(v.verify(self.c,self.proof)[0])
    def test_invalid_encoding_and_out_of_field(self):
        bad=copy.deepcopy(self.proof); bad['nodes'][0]['sigma']='00'*48
        self.assertFalse(p.verify(self.pub,self.pin,self.c,bad)[0])
        bad=copy.deepcopy(self.proof); bad['nodes'][0]['mu'][0]=str(p.R)
        self.assertFalse(p.verify(self.pub,self.pin,self.c,bad)[0])
    def test_duplicate_and_zero_coefficient_challenge(self):
        c=copy.deepcopy(self.c); c['pairs'].append(c['pairs'][0])
        self.assertFalse(p.verify(self.pub,self.pin,c,self.proof)[0])
        c=copy.deepcopy(self.c); c['pairs'][0]['coefficient']='0'
        self.assertFalse(p.verify(self.pub,self.pin,c,self.proof)[0])
    def test_pinned_key_and_metadata_tamper(self):
        self.assertFalse(p.verify(self.pub,'00'*32,self.c,self.proof)[0])
        pub=copy.deepcopy(self.pub); pub['node_tags'][0]['descriptor']['blocks']+=1
        self.assertFalse(p.verify(pub,self.pin,self.c,self.proof)[0])
    def test_signature_baseline(self):
        proof,_=p.prove(self.directory,self.pub,self.c,'ed25519')
        self.assertTrue(p.verify(self.pub,self.pin,self.c,proof,'ed25519')[0])
        bad=copy.deepcopy(proof); bad['nodes'][0]['records'][0]['data']='00'*self.pub['block_bytes']
        self.assertFalse(p.verify(self.pub,self.pin,self.c,bad,'ed25519')[0])
    def test_reconstruction_every_k_of_n(self):
        for keep in itertools.combinations(range(6),4): self.assertTrue(p.reconstruct(self.directory,self.pub,keep))
        with self.assertRaises(ValueError): p.reconstruct(self.directory,self.pub,[0,1,2])
    def test_aead_wrong_key_rejected(self):
        from cryptography.exceptions import InvalidTag
        cipher=p.AESGCM(p.AESGCM.generate_key(bit_length=256)); nonce=bytes(12); ct=cipher.encrypt(nonce,b'test',b'aad')
        with self.assertRaises(InvalidTag): cipher.decrypt(nonce,ct[:-1]+bytes([ct[-1]^1]),b'aad')
        wrong=p.AESGCM(p.AESGCM.generate_key(bit_length=256))
        with self.assertRaises(InvalidTag): wrong.decrypt(nonce,ct,b'aad')
        with self.assertRaises(InvalidTag): cipher.decrypt(nonce,ct,b'wrong-aad')
    def test_timeout_policy(self):
        v=p.SessionVerifier(self.pub,self.pin)
        self.assertEqual(v.verify(self.c,self.proof,elapsed_ms=2,timeout_ms=1),(False,'timeout_policy'))
    def test_sampling_seed_domains_do_not_overlap(self):
        from run_experiment import sampling_seed
        values=[sampling_seed('fault-query',seed,fraction,q,rep) for seed in [2023090801,2023090802,2023090803] for fraction in [.01,.05,.2] for q in [4,16,64] for rep in range(100)]
        self.assertEqual(len(values),len(set(values)))
        self.assertNotEqual(sampling_seed('fault-set',1,.01),sampling_seed('fault-query',1,.01))
    def test_independent_curve_and_pairing_implementation(self):
        from py_ecc.bls.hash_to_curve import hash_to_G1,hash_to_G2
        from py_ecc.bls.point_compression import compress_G1,compress_G2,decompress_G1,decompress_G2
        from py_ecc.optimized_bls12_381 import multiply,add,Z1,pairing
        msg=b'cross-library-test'; a=p.P1.hash_to_group(msg,p.DST); b=hash_to_G1(msg,p.DST,hashlib.sha256)
        self.assertEqual(a.compress(),int(compress_G1(b)).to_bytes(48,'big'))
        self.assertEqual(a.scalar_mul(123456789).compress(),int(compress_G1(multiply(b,123456789))).to_bytes(48,'big'))
        g=hash_to_G2(b'I12 fixed public generator v1',b'I12_SW08_BLS12381G2_XMD:SHA-256_SSWU_RO_V1',hashlib.sha256)
        z=compress_G2(g); self.assertEqual(p.G2.compress(),b''.join(int(v).to_bytes(48,'big') for v in z))
        # Independently verify one real node's aggregate, without calling p.verify.
        proof=self.proof['nodes'][0]; node=proof['node']; name=self.pub['node_tags'][node]['descriptor']['name']; acc=Z1
        for item in self.c['pairs']:
            if item['node']==node:
                pt=hash_to_G1(bytes.fromhex(name)+item['index'].to_bytes(8,'big'),p.DST,hashlib.sha256)
                acc=add(acc,multiply(pt,int(item['coefficient'])))
        for u,mu in zip(self.pub['generators'],proof['mu']): acc=add(acc,multiply(decompress_G1(int(u,16)),int(mu)))
        pk=bytes.fromhex(self.pub['public_key']); pk2=decompress_G2((int.from_bytes(pk[:48],'big'),int.from_bytes(pk[48:],'big')))
        self.assertEqual(pairing(g,decompress_G1(int(proof['sigma'],16))),pairing(pk2,acc))

if __name__=='__main__': unittest.main(verbosity=2)
