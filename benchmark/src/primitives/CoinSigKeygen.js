import { params } from '../../../servers/dist/globalConfig';
import CoinSig from '../../../servers/dist/CoinSig';

const prepare = () => ([[], []]);

const before = () => ([]);

const keygen = () => CoinSig.keygen(params);

const CoinSigKeygenBenchmark = {
  name: 'CoinSigKeygen',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: keygen, // takes ...a, ...c
};

export default CoinSigKeygenBenchmark;
