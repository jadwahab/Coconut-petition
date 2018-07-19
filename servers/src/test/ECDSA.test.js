import * as crypto from 'crypto';
import { expect, assert } from 'chai';
import { before, describe, it, xit } from 'mocha';
import { ctx } from '../globalConfig';

describe('Reference ECDSA', () => {
  let rng;
  let g1;
  let o;
  before(() => {
    g1 = new ctx.ECP();
    const x = new ctx.BIG(0);
    const y = new ctx.BIG(0);

    x.rcopy(ctx.ROM_CURVE.CURVE_Gx);
    y.rcopy(ctx.ROM_CURVE.CURVE_Gy);
    g1.setxy(x, y);

    const RAW = crypto.randomBytes(128);

    rng = new ctx.RAND();
    rng.clean();
    rng.seed(RAW.length, RAW);

    o = new ctx.BIG(0);
    o.rcopy(ctx.ROM_CURVE.CURVE_Order);
  });

  it('Correctly signs and verifies message', () => {
    const m = 'Some string message';
    const C = [];
    const D = [];
    const sha = ctx.ECDH.HASH_TYPE;

    const sk = ctx.BIG.randomnum(o, rng);
    const skBytes = [];
    sk.toBytes(skBytes);
    const pk = g1.mul(sk);
    const pkBytes = [];
    pk.toBytes(pkBytes);


    // signing, where C and D are signatures (in bytes)
    expect(ctx.ECDH.ECPSP_DSA(sha, rng, skBytes, m, C, D))
      .to
      .be
      .equal(0);

    // verification
    expect(ctx.ECDH.ECPVP_DSA(sha, pkBytes, m, C, D))
      .to
      .be
      .equal(0);
  });
});
