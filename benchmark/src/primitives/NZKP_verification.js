import { params } from '../../../servers/dist/globalConfig';
import { prepareProofOfSecret, verifyProofOfSecret } from '../../../servers/dist/auxiliary';

const prepare = () => ([[], []]);

const before = () => {
  const [G, o, g1, g2, e] = params;

  const x = G.ctx.BIG.randomnum(G.order, G.rngGen);

  // generate some random gr each time (gr = g2^r)
  const r = G.ctx.BIG.randomnum(G.order, G.rngGen);
  const gr = G.ctx.PAIR.G2mul(g2, r);

  // do what is actually done, i.e. use some pubkey
  const pkBytes = [];
  const sk = G.ctx.BIG.randomnum(G.order, G.rngGen);
  const pk = G.gen1.mul(sk);
  pk.toBytes(pkBytes);
  const verifierStr = pkBytes.join('');

  const pub = G.ctx.PAIR.G2mul(gr, x);
  const proof = prepareProofOfSecret(params, x, verifierStr, gr);

  return [pub, proof, verifierStr, gr];
};

const verifyNZKP = (pub, proof, verifierStr, gr) => {
  return verifyProofOfSecret(params, pub, proof, verifierStr, gr);
};

const NZKPVerificationBenchmark = {
  name: 'NZKP_verification',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: verifyNZKP, // takes ...a, ...c
};

export default NZKPVerificationBenchmark;
