import { params } from '../../../servers/dist/globalConfig';
import { prepareProofOfSecret } from '../../../servers/dist/auxiliary';

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

  return [x, verifierStr, gr];
};

const prepareNZKP = (x, verifierStr, proofBase) => {
  return prepareProofOfSecret(params, x, verifierStr, proofBase);
};

const NZKPCreationBenchmark = {
  name: 'NZKP_creation',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: prepareNZKP, // takes ...a, ...c
};

export default NZKPCreationBenchmark;
