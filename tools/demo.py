"""Generate public verification examples; discard test secrets on exit."""
import bootstrap
import argparse
import copy
import json
import tempfile
from pathlib import Path

import protocol as p


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path('demo-output'))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='storage-audit-demo-') as tmp:
        pub = p.setup(Path(tmp) / 'case', 1025, 6, 20230908, s=4)
        challenge = p.challenge(pub, 6, 1234)
        proof, _ = p.prove(Path(tmp) / 'case', pub, challenge)
        accepted, reason = p.verify(pub, pub['signing_public'], challenge, proof)
        bad = copy.deepcopy(proof)
        bad['nodes'][0]['mu'][0] = str((int(bad['nodes'][0]['mu'][0]) + 1) % p.R)
        rejected = not p.verify(pub, pub['signing_public'], challenge, bad)[0]
        recovered = p.reconstruct(Path(tmp) / 'case', pub, [0, 1, 2, 3])
        assert accepted and rejected and recovered
        for name, obj in [('public.json', pub), ('challenge.json', challenge), ('proof.json', proof)]:
            p.save_json(args.output / name, obj)
        summary = {'valid_proof_accepted': accepted, 'verification_reason': reason,
                   'tampered_proof_rejected': rejected, 'recovered_from_four_of_six': recovered,
                   'scope': 'fresh functional example; not a performance benchmark'}
        p.save_json(args.output / 'summary.json', summary)
        print(json.dumps(summary, ensure_ascii=False))


if __name__ == '__main__':
    main()
