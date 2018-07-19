import * as crypto from 'crypto';
import { params } from '../../../servers/dist/globalConfig';


const prepare = () => ([[], []]);

const before = () => {
  const [G, o, g1, g2, e] = params;

  const skBytes = [];
  const pkBytes = [];
  // generate keypair for signing messages
  const sk = G.ctx.BIG.randomnum(o, G.rngGen);
  const pk = g1.mul(sk);
  pk.toBytes(pkBytes);
  sk.toBytes(skBytes);

  const sha = G.ctx.ECDH.HASH_TYPE;
  const C = [];
  const D = [];

  const requestStr = crypto.randomBytes(64).toString('hex');
  G.ctx.ECDH.ECPSP_DSA(sha, G.rngGen, skBytes, requestStr, C, D);

  return [G, sha, pkBytes, requestStr, C, D];
};

const ECDSA_ver = (G, sha, pk, requestStr, C, D) => {
  return G.ctx.ECDH.ECPVP_DSA(sha, pk, requestStr, C, D);
};

const ECDSA_Verify = {
  name: 'ECDSA_Verify',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: ECDSA_ver, // takes ...a, ...c
};

export default ECDSA_Verify;
