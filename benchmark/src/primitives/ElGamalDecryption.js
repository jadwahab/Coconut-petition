import { params } from '../../../servers/dist/globalConfig';
import ElGamal from '../../../servers/dist/ElGamal';

const prepare = () => ([[], []]);

const before = () => {
  const [G, o, g1, g2, e] = params;

  const [ElGamalSK, ElGamalPK] = ElGamal.keygen(params);

  const x = G.ctx.BIG.randomnum(G.order, G.rngGen);

  const r = G.ctx.BIG.randomnum(G.order, G.rngGen);
  const base = G.ctx.PAIR.G1mul(G.gen1, r);

  const c = ElGamal.encrypt(params, ElGamalPK, x, base);

  return [ElGamalSK, c];
};

const ElGamalDecryption = (sk, c) => {
  return ElGamal.decrypt(params, sk, c);
};

const ElGamalDecryptionBenchmark = {
  name: 'ElGamalDecryption',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: ElGamalDecryption, // takes ...a, ...c
};

export default ElGamalDecryptionBenchmark;
