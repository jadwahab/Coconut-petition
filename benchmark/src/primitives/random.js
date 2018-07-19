import BpGroup from '../../../servers/dist/BpGroup';

const prepare = () => {
  const G = new BpGroup();

  return [[G], []];
};

const before = () => ([]);

const getRandomBIG = G => G.ctx.BIG.randomnum(G.order, G.rngGen);

const randomBenchmark = {
  name: 'randomBIG',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: getRandomBIG, // takes ...a, ...c
};

export default randomBenchmark;
