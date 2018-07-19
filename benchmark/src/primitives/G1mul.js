import BpGroup from '../../../servers/dist/BpGroup';
import { params } from '../../../servers/dist/globalConfig';

const prepare = () => ([[], []]);

const before = () => {
  const [G, o, g1, g2, e] = params;
  const x = G.ctx.BIG.randomnum(G.order, G.rngGen);
  return [G, g1, x];
};

const mul = (G, g1, x) => {
  return G.ctx.PAIR.G1mul(g1, x);
};

const G1mul = {
  name: 'G1mul',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: mul, // takes ...a, ...c
};

export default G1mul;

