import * as crypto from 'crypto';
import { params } from '../../../servers/dist/globalConfig';


const prepare = () => ([[], []]);

const before = () => {
  const [G, o, g1, g2, e] = params;

  const skBytes = [];
  // generate keypair for signing messages
  const sk = G.ctx.BIG.randomnum(o, G.rngGen);
  sk.toBytes(skBytes);

  const sha = G.ctx.ECDH.HASH_TYPE;
  const C = [];
  const D = [];

  const requestStr = crypto.randomBytes(64).toString('hex');

  return [G, sha, skBytes, requestStr, C, D];
};

const ECDSA_Sig = (G, sha, sk, requestStr, C, D) => {
  return G.ctx.ECDH.ECPSP_DSA(sha, G.rngGen, sk, requestStr, C, D);
};

const ECDSA_Sign = {
  name: 'ECDSA_Sign',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: ECDSA_Sig, // takes ...a, ...c
};

export default ECDSA_Sign;
