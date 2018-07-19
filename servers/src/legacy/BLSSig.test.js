import { describe, it, xit } from 'mocha';
import * as chai from 'chai';
import BLSSig from './BLSSig';
import BpGroup from '../BpGroup';

describe('Boneh–Lynn–Shacham-based Signature scheme', () => {
  describe('Setup', () => {
    const params = BLSSig.setup();
    const [G, o, g1, g2, e] = params;

    it('Returns BpGroup Object', () => {
      chai.assert.isNotNull(G);
      chai.assert.isTrue(G instanceof (BpGroup));
    });

    it('Returns Group Order', () => {
      chai.assert.isNotNull(o);
      chai.assert.isTrue(o instanceof (G.ctx.BIG));
    });

    it('Returns Gen1', () => {
      chai.assert.isNotNull(g1);
      chai.assert.isTrue(g1 instanceof (G.ctx.ECP));
    });

    it('Returns Gen2', () => {
      chai.assert.isNotNull(g2);
      chai.assert.isTrue(g2 instanceof (G.ctx.ECP2));
    });

    it('Returns Pair function', () => {
      chai.assert.isNotNull(e);
      chai.assert.isTrue(e instanceof (Function));
    });
  });

  describe('Keygen', () => {
    const params = BLSSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = BLSSig.keygen(params);


    it('Returns Secret Key x', () => {
      chai.assert.isTrue(sk instanceof (G.ctx.BIG));
    });

    it('Returns Valid Private Key v = x * g2', () => {
      chai.assert.isTrue(pk.equals(G.ctx.PAIR.G2mul(g2, sk)));
    });
  });

  // sig = sk * H(m)
  describe('Sign', () => {
    const params = BLSSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = BLSSig.keygen(params);

    const m = 'Hello World!';

    const signature = BLSSig.sign(params, sk, m);

    it('signature = sk * H(m)', () => {
      const h = G.hashToPointOnCurve(m);

      const sig_test = G.ctx.PAIR.G1mul(h, sk);
      chai.assert.isTrue(signature.equals(sig_test));
    });
  });

  // e(sig, g2) = e(h, pk)
  describe('Verify', () => {
    const params = BLSSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = BLSSig.keygen(params);

    const m = 'Hello World!';
    const sig = BLSSig.sign(params, sk, m);

    it('Successful verification for original message', () => {
      chai.assert.isTrue(BLSSig.verify(params, pk, m, sig));
    });

    it('Failed verification for another message', () => {
      const m2 = 'Other Hello World!';
      chai.assert.isNotTrue(BLSSig.verify(params, pk, m2, sig));
    });
  });

  describe('Aggregate', () => {
    it('Aggregation(sig1) = sig1', () => {
      const params = BLSSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = BLSSig.keygen(params);

      const m = 'Hello World!';
      const sig = BLSSig.sign(params, sk, m);
      const aggregateSignature = BLSSig.aggregateSignatures(params, [sig]);

      chai.assert.isTrue(sig.equals(aggregateSignature));
    });
  });

  describe('Aggregate Verification', () => {
    it('Works for single signature', () => {
      const params = BLSSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = BLSSig.keygen(params);

      const m = 'Hello World!';
      const sig = BLSSig.sign(params, sk, m);
      const aggregateSignature = BLSSig.aggregateSignatures(params, [sig]);

      chai.assert.isTrue(BLSSig.verifyAggregation(params, [pk], m, aggregateSignature));
    });

    it('Works for three distinct signatures', () => {
      const params = BLSSig.setup();
      const [G, o, g1, g2, e] = params;

      const messagesToSign = 3;
      const pks = [];
      const signatures = [];

      const m = 'Hello World!';

      for (let i = 0; i < messagesToSign; i++) {
        const [sk, pk] = BLSSig.keygen(params);
        pks.push(pk);
        const signature = BLSSig.sign(params, sk, m);
        signatures.push(signature);
      }

      const aggregateSignature = BLSSig.aggregateSignatures(params, signatures);

      chai.assert.isTrue(BLSSig.verifyAggregation(params, pks, m, aggregateSignature));
    });

    it("Doesn't work when one of three signatures is on different message", () => {
      const params = BLSSig.setup();
      const messagesToSign = 2;
      const pks = [];
      const signatures = [];

      const m = 'Hello World!';

      for (let i = 0; i < messagesToSign; i++) {
        const [sk, pk] = BLSSig.keygen(params);
        pks.push(pk);
        const signature = BLSSig.sign(params, sk, m);
        signatures.push(signature);
      }

      const m2 = 'Malicious Hello World';
      const [skm, pkm] = BLSSig.keygen(params);
      pks.push(pkm);
      const maliciousSignature = BLSSig.sign(params, skm, m2);
      signatures.push(maliciousSignature);

      const aggregateSignature = BLSSig.aggregateSignatures(params, signatures);

      chai.assert.isNotTrue(BLSSig.verifyAggregation(params, pks, m, aggregateSignature));
    });
  });
});
