import { params } from '../../../servers/dist/globalConfig';
import CoinSig from '../../../servers/dist/CoinSig';

const prepare = () => ([[], []]);

const before = () => {
  const ITERATIONS = 10;
  const pks = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const [sk, pk] = CoinSig.keygen(params);
    pks.push(pk);
  }

  return [pks];
};

const PublicKeyAggregation = (pks) => {
  return CoinSig.aggregatePublicKeys(params, pks);
};

const PublicKeyAggregation_10 = {
  name: 'PublicKeyAggregation_10',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: PublicKeyAggregation, // takes ...a, ...c
};

export default PublicKeyAggregation_10;
