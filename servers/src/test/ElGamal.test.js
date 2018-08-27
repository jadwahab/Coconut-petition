import { before, beforeEach, describe, it, xit } from 'mocha';
import { expect, assert } from 'chai';
import ElGamal from '../ElGamal';
import CredSig from '../CredSig';
import { hashToPointOnCurve } from '../Proofs';

describe('ElGamal Encryption', () => {
  describe('Keygen', () => {
    const params = CredSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = ElGamal.keygen(params);
    it('Returns valid secret key of type BIG', () => {
      assert.isTrue(sk instanceof (G.ctx.BIG));
    });

    it('Returns valid public key of type G1Elem, such that pk = g1^sk', () => {
      assert.isTrue(pk instanceof (G.ctx.ECP));
      assert.isTrue(pk.equals(G.ctx.PAIR.G1mul(g1, sk)));
    });
  });

  describe('Encryption', () => {
    const params = CredSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = ElGamal.keygen(params);

    // generate some dummy h and m:
    const h = hashToPointOnCurve('Dummy generator');
    const m = G.ctx.BIG.randomnum(G.order, G.rngGen);

    const [a, b, k] = ElGamal.encrypt(params, pk, m, h);

    // a - G1; g1^k
    // b - G1, pk^k + h^m
    // k - BIG
    it('Returns a of type G1Elem, such that a = g1^k', () => {
      assert.isTrue(a instanceof (G.ctx.ECP));
      assert.isTrue(a.equals(G.ctx.PAIR.G1mul(g1, k)));
    });

    it('Returns b of type G1Elem, such that b = pk^k + h^m', () => {
      assert.isTrue(b instanceof (G.ctx.ECP));
      const b1 = G.ctx.PAIR.G1mul(pk, k);
      const b2 = G.ctx.PAIR.G1mul(h, m);

      b1.add(b2);
      b1.affine();

      assert.isTrue(b.equals(b1));
    });

    it('Returns k of type BIG', () => {
      assert.isTrue(k instanceof (G.ctx.BIG));
    });
  });

  describe('Decryption', () => {
    it('Can recover encrypted h^m', () => {
      const params = CredSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = ElGamal.keygen(params);

      const h = hashToPointOnCurve('Dummy generator');
      const m = G.ctx.BIG.randomnum(G.order, G.rngGen);

      const h_m = G.ctx.PAIR.G1mul(h, m);
      const [a, b, k] = ElGamal.encrypt(params, pk, m, h);

      const decrypted = ElGamal.decrypt(params, sk, [a, b]);

      assert.isTrue(h_m.equals(decrypted));
    });
  });

  describe('To and from Bytes', () => {
    it('Can be converted to and from bytes representation', () => {
      const params = CredSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = ElGamal.keygen(params);
      const PKBytes = ElGamal.getPKBytes(pk);
      const recreatedPK = ElGamal.getPKFromBytes(params, PKBytes);
      assert.isTrue(pk.equals(recreatedPK));
    });
  });
});
