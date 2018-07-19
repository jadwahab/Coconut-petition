import { describe, it, xit } from 'mocha';
import { expect, assert } from 'chai';
import PSSig from './PSSig';
import BpGroup from '../BpGroup';

describe('Pointcheval-Sanders Short Randomizable Signatures scheme', () => {
  describe('Setup', () => {
    const params = PSSig.setup();
    const [G, o, g1, g2, e] = params;

    it('Returns BpGroup Object', () => {
      assert.isNotNull(G);
      assert.isTrue(G instanceof (BpGroup));
    });

    it('Returns Group Order', () => {
      assert.isNotNull(o);
      assert.isTrue(o instanceof (G.ctx.BIG));
    });

    it('Returns Gen1', () => {
      assert.isNotNull(g1);
      assert.isTrue(g1 instanceof (G.ctx.ECP));
    });

    it('Returns Gen2', () => {
      assert.isNotNull(g2);
      assert.isTrue(g2 instanceof (G.ctx.ECP2));
    });

    it('Returns Pair function', () => {
      assert.isNotNull(e);
      assert.isTrue(e instanceof (Function));
    });
  });

  describe('Keygen', () => {
    const params = PSSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = PSSig.keygen(params);

    const [x, y] = sk;
    const [g, X, Y] = pk;

    it('Returns Secret Key (x,y)', () => {
      assert.isTrue(x instanceof (G.ctx.BIG));
      assert.isTrue(y instanceof (G.ctx.BIG));
    });

    describe('Returns Valid Private Key (g,X,Y)', () => {
      it('g = g2', () => {
        assert.isTrue(g2.equals(g));
      });

      it('X = g2*x', () => {
        assert.isTrue(X.equals(G.ctx.PAIR.G2mul(g2, x)));
      });

      it('Y = g2*y', () => {
        assert.isTrue(Y.equals(G.ctx.PAIR.G2mul(g2, y)));
      });
    });
  });

  // h, sig = (x+y*m) * h
  describe('Sign', () => {
    const params = PSSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = PSSig.keygen(params);
    const [x, y] = sk;

    let m = 'Hello World!';

    const signature = PSSig.sign(params, sk, m);
    const [sig1, sig2] = signature;


    it('For signature(sig1, sig2), sig2 = ((x+y*(m mod p)) mod p) * sig1', () => {
      m = G.hashToBIG(m);
      const mcpy = new G.ctx.BIG(m);
      mcpy.mod(o);

      const t1 = G.ctx.BIG.mul(y, mcpy);

      const xDBIG = new G.ctx.DBIG(0);
      for (let i = 0; i < G.ctx.BIG.NLEN; i++) {
        xDBIG.w[i] = x.w[i];
      }
      t1.add(xDBIG);
      const K = t1.mod(o);

      const sig_test = G.ctx.PAIR.G1mul(sig1, K);
      assert.isTrue(sig2.equals(sig_test));
    });
  });


  describe('Verify', () => {
    describe('With sk = (42, 513)', () => {
      const params = PSSig.setup();
      const [G, o, g1, g2, e] = params;

      // keygen needs to be done 'manually'
      const x = new G.ctx.BIG(42);
      const y = new G.ctx.BIG(513);

      const sk = [x, y];
      const pk = [g2, g2.mul(x), g2.mul(y)];

      const m = 'Hello World!';
      const sig = PSSig.sign(params, sk, m);

      it('Successful verification for original message', () => {
        assert.isTrue(PSSig.verify(params, pk, m, sig));
      });

      it('Failed verification for another message', () => {
        const m2 = 'Other Hello World!';
        assert.isNotTrue(PSSig.verify(params, pk, m2, sig));
      });
    });

    describe("With 'proper' random", () => {
      const params = PSSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = PSSig.keygen(params);
      const [x, y] = sk;

      const m = 'Hello World!';
      const sig = PSSig.sign(params, sk, m);

      it('Successful verification for original message', () => {
        assert.isTrue(PSSig.verify(params, pk, m, sig));
      });

      it('Failed verification for another message', () => {
        const m2 = 'Other Hello World!';
        assert.isNotTrue(PSSig.verify(params, pk, m2, sig));
      });
    });
  });

  describe('Randomize', () => {
    const params = PSSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = PSSig.keygen(params);
    const [x, y] = sk;

    const m = 'Hello World!';
    let sig = PSSig.sign(params, sk, m);
    sig = PSSig.randomize(params, sig);

    it('Successful verification for original message with randomized signature', () => {
      assert.isTrue(PSSig.verify(params, pk, m, sig));
    });

    it('Failed verification for another message with randomized signature', () => {
      const m2 = 'Other Hello World!';
      assert.isNotTrue(PSSig.verify(params, pk, m2, sig));
    });
  });

  // todo: better test for whether aggregation is correct
  describe('Aggregate', () => {
    it('Aggregation(s1) = s1', () => {
      const params = PSSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = PSSig.keygen(params);
      const [x, y] = sk;

      const m = 'Hello World!';
      const signature = PSSig.sign(params, sk, m);
      const aggregateSig = PSSig.aggregateSignatures(params, [signature]);

      assert.isTrue(signature[1].equals(aggregateSig[1]));
    });
  });


  describe('Aggregate Verification', () => {
    describe('Aggregate Verification', () => {
      it('Works for single signature', () => {
        const params = PSSig.setup();
        const [G, o, g1, g2, e] = params;
        const [sk, pk] = PSSig.keygen(params);

        const m = 'Hello World!';
        const sig = PSSig.sign(params, sk, m);
        const aggregateSignature = PSSig.aggregateSignatures(params, [sig]);

        assert.isTrue(PSSig.verifyAggregation(params, [pk], m, aggregateSignature));
      });

      it('Works for three distinct signatures', () => {
        const params = PSSig.setup();
        const [G, o, g1, g2, e] = params;

        const messagesToSign = 3;
        const pks = [];
        const signatures = [];

        const m = 'Hello World!';

        for (let i = 0; i < messagesToSign; i++) {
          const [sk, pk] = PSSig.keygen(params);
          pks.push(pk);
          const signature = PSSig.sign(params, sk, m);
          signatures.push(signature);
        }

        const aggregateSignature = PSSig.aggregateSignatures(params, signatures);

        assert.isTrue(PSSig.verifyAggregation(params, pks, m, aggregateSignature));
      });

      it("Doesn't work when one of three signatures is on different message", () => {
        const params = PSSig.setup();
        const [G, o, g1, g2, e] = params;

        const messagesToSign = 2;
        const pks = [];
        const signatures = [];

        const m = 'Hello World!';

        for (let i = 0; i < messagesToSign; i++) {
          const [sk, pk] = PSSig.keygen(params);
          pks.push(pk);
          const signature = PSSig.sign(params, sk, m);
          signatures.push(signature);
        }

        const m2 = 'Malicious Hello World';
        const [skm, pkm] = PSSig.keygen(params);
        pks.push(pkm);
        const maliciousSignature = PSSig.sign(params, skm, m2);
        signatures.push(maliciousSignature);

        const aggregateSignature = PSSig.aggregateSignatures(params, signatures);

        assert.isNotTrue(PSSig.verifyAggregation(params, pks, m, aggregateSignature));
      });
    });
  });
});
