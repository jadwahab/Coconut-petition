import BpGroup from '../../../servers/dist/BpGroup';

const prepare = () => {
  const G = new BpGroup();
  const g1 = G.gen1;
  const g2 = G.gen2;

  return [[G], [G, g1, g2]];
};

const before = (G, g1, g2) => {
  const r1 = G.ctx.BIG.randomnum(G.order, G.rngGen);
  const r2 = G.ctx.BIG.randomnum(G.order, G.rngGen);

  const G1elem = G.ctx.PAIR.G1mul(g1, r1);
  const G2elem = G.ctx.PAIR.G2mul(g2, r2);

  return [G1elem, G2elem];
};

const doPairing = (G, G1elem, G2elem) => G.pair(G1elem, G2elem);

const pairingBenchmark = {
  name: 'pairing',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: doPairing, // takes ...a, ...c
};

export default pairingBenchmark;
