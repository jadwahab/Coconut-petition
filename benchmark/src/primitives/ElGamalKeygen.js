import { params } from '../../../servers/dist/globalConfig';
import ElGamal from '../../../servers/dist/ElGamal';

const prepare = () => ([[], []]);

const before = () => ([]);

const ElGamalKeygen = () => ElGamal.keygen(params);

const ElGamalKeygenBenchmark = {
  name: 'ElGamalKeygen',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: ElGamalKeygen, // takes ...a, ...c
};

export default ElGamalKeygenBenchmark;
