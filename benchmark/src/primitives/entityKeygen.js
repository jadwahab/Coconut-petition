import BpGroup from '../../../servers/dist/BpGroup';

const prepare = () => {
  const G = new BpGroup();

  return [[G], []];
};

const before = () => ([]);

const keygen = (G) => {
  const skBytes = [];
  const pkBytes = [];
  const sk = G.ctx.BIG.randomnum(G.order, G.rngGen);
  const pk = G.gen1.mul(sk);
  sk.toBytes(skBytes);
  pk.toBytes(pkBytes);
  return [skBytes, pkBytes];
};

const EntityKeygenBenchmark = {
  name: 'EntityKeygen',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: keygen, // takes ...a, ...c
};

export default EntityKeygenBenchmark;

