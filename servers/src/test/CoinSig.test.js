import { before, beforeEach, describe, it, xit } from 'mocha';
import { expect, assert } from 'chai';
import { ctx } from '../globalConfig';
import CoinSig from '../CoinSig';
import BpGroup from '../BpGroup';
import { getRandomCoinId, hashToBIG, hashG2ElemToBIG } from '../auxiliary';
import ElGamal from '../ElGamal';
import { getSigningCoin } from '../SigningCoin';
import { getIssuedCoin } from '../IssuedCoin';

const generateCoinSecret = (params) => {
  const [G, o, g1, g2, e] = params;
  const sk = G.ctx.BIG.randomnum(G.order, G.rngGen);
  const pk = G.ctx.PAIR.G2mul(g2, sk);
  return [sk, pk];
};

describe('CoinSig Scheme', () => {
  describe('Setup', () => {
    const params = CoinSig.setup();
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
    const params = CoinSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = CoinSig.keygen(params);

    const [x0, x1, x2, x3, x4] = sk;
    const [g, X0, X1, X2, X3, X4] = pk;

    it('Returns Secret Key (x0, x1, x2, x3, x4)', () => {
      assert.isTrue(x0 instanceof (G.ctx.BIG));
      assert.isTrue(x1 instanceof (G.ctx.BIG));
      assert.isTrue(x2 instanceof (G.ctx.BIG));
      assert.isTrue(x3 instanceof (G.ctx.BIG));
      assert.isTrue(x4 instanceof (G.ctx.BIG));
    });

    describe('Returns Valid Private Key (g, X0, X1, X2, X3, X4)', () => {
      it('g = g2', () => {
        assert.isTrue(g2.equals(g));
      });

      it('X0 = g2*x0', () => {
        assert.isTrue(X0.equals(G.ctx.PAIR.G2mul(g2, x0)));
      });

      it('X1 = g2*x1', () => {
        assert.isTrue(X1.equals(G.ctx.PAIR.G2mul(g2, x1)));
      });

      it('X2 = g2*x2', () => {
        assert.isTrue(X2.equals(G.ctx.PAIR.G2mul(g2, x2)));
      });

      it('X3 = g2*x3', () => {
        assert.isTrue(X3.equals(G.ctx.PAIR.G2mul(g2, x3)));
      });

      it('X4 = g2*x4', () => {
        assert.isTrue(X4.equals(G.ctx.PAIR.G2mul(g2, x4)));
      });
    });
  });

  // h, sig = (x0 + x1*a1 + x2*a2 + ...) * h
  describe('Sign', () => {
    it('For signature(sig1, sig2), sig2 = (x0 + x1*a1 + x2*a2 + ...) * sig1', () => {
      const params = CoinSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = CoinSig.keygen(params);
      const [x0, x1, x2, x3, x4] = sk;

      const coin_params = CoinSig.setup();
      const [coin_sk, coin_pk] = generateCoinSecret(coin_params);
      const coin_id = G.ctx.BIG.randomnum(G.order, G.rngGen);
      const ID = G.ctx.PAIR.G1mul(g1, coin_id);
      const dummyCoin = {
        value: 42,
        ttl: new Date().getTime(),
        v: coin_pk,
        ID: ID,
      };

      const signature = CoinSig.sign(params, sk, dummyCoin);
      const [sig1, sig2] = signature;

      const a1 = new G.ctx.BIG(dummyCoin.value);
      a1.norm();
      const a2 = hashToBIG(dummyCoin.ttl.toString());
      const a3 = hashG2ElemToBIG(dummyCoin.v);
      const a4 = hashG2ElemToBIG(dummyCoin.ID);

      const a1_cpy = new G.ctx.BIG(a1);
      a1_cpy.mod(o);
      const a2_cpy = new G.ctx.BIG(a2);
      a2_cpy.mod(o);
      const a3_cpy = new G.ctx.BIG(a3);
      a3_cpy.mod(o);
      const a4_cpy = new G.ctx.BIG(a4);
      a4_cpy.mod(o);

      const t1 = G.ctx.BIG.mul(x1, a1_cpy);
      const t2 = G.ctx.BIG.mul(x2, a2_cpy);
      const t3 = G.ctx.BIG.mul(x3, a3_cpy);
      const t4 = G.ctx.BIG.mul(x4, a4_cpy);

      const x0DBIG = new G.ctx.DBIG(0);
      for (let i = 0; i < G.ctx.BIG.NLEN; i++) {
        x0DBIG.w[i] = x0.w[i];
      }

      x0DBIG.add(t1);
      x0DBIG.add(t2);
      x0DBIG.add(t3);
      x0DBIG.add(t4);

      const K = x0DBIG.mod(o);

      const sig_test = G.ctx.PAIR.G1mul(sig1, K);
      assert.isTrue(sig2.equals(sig_test));
    });
  });

  describe('Verify', () => {
    let params;
    let G;
    let o;
    let g1;
    let g2;
    let e;
    let sk;
    let pk;
    let dummyCoin;
    let testCoin;
    let sig;
    let coin_params;
    before(() => {
      params = CoinSig.setup();
      [G, o, g1, g2, e] = params;
      [sk, pk] = CoinSig.keygen(params);

      coin_params = CoinSig.setup();
      const [coin_sk, coin_pk] = generateCoinSecret(coin_params);
      const coin_id = G.ctx.BIG.randomnum(G.order, G.rngGen);
      const ID = G.ctx.PAIR.G1mul(g1, coin_id);
      dummyCoin = {
        value: 42,
        ttl: new Date().getTime().toString(),
        v: coin_pk,
        ID: ID,
      };

      testCoin = {};

      sig = CoinSig.sign(params, sk, dummyCoin);
    });

    // 'resets' the test coin
    beforeEach(() => {
      testCoin.ttl = dummyCoin.ttl;
      testCoin.ID = new G.ctx.ECP();
      testCoin.ID.copy(dummyCoin.ID);
      testCoin.value = dummyCoin.value;
      testCoin.v = new G.ctx.ECP2();
      testCoin.v.copy(dummyCoin.v);
    });

    it('Successful verification of original coin', () => {
      assert.isTrue(CoinSig.verify(params, pk, dummyCoin, sig));
    });

    it('Failed verification for coin with different value', () => {
      testCoin.value = 256;
      assert.isNotTrue(CoinSig.verify(params, pk, testCoin, sig));
    });

    it('Failed verification for coin with different ttl', () => {
      // ttl of actual coin will never be equal to that
      testCoin.value = new Date().getTime() - 12345678;
      assert.isNotTrue(CoinSig.verify(params, pk, testCoin, sig));
    });

    it('Failed verification for coin with different id, hence ID', () => {
      const newCoinIde = getRandomCoinId();
      testCoin.ID = G.ctx.PAIR.G1mul(g1, newCoinIde);
      assert.isNotTrue(CoinSig.verify(params, pk, testCoin, sig));
    });

    it('Failed verification for coin with different secret', () => {
      const [new_coin_sk, new_coin_pk] = generateCoinSecret(coin_params);
      testCoin.v = new_coin_pk;
      assert.isNotTrue(CoinSig.verify(params, pk, testCoin, sig));
    });
  });

  describe('Randomize', () => {
    const params = CoinSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = CoinSig.keygen(params);

    const coin_params = CoinSig.setup();
    const [coin_sk, coin_pk] = generateCoinSecret(coin_params);
    const coin_id = G.ctx.BIG.randomnum(G.order, G.rngGen);
    const ID = G.ctx.PAIR.G1mul(g1, coin_id);
    const dummyCoin = {
      value: 42,
      ttl: new Date().getTime(),
      v: coin_pk,
      ID: ID,
    };

    let sig = CoinSig.sign(params, sk, dummyCoin);
    sig = CoinSig.randomize(params, sig);

    it('Successful verification for original coin with randomized signature', () => {
      assert.isTrue(CoinSig.verify(params, pk, dummyCoin, sig));
    });

    it('Failed verification for modified coin with the same randomized signature', () => {
      dummyCoin.value = 43;
      assert.isNotTrue(CoinSig.verify(params, pk, dummyCoin, sig));
    });
  });

  describe('Aggregate', () => {
    it('Aggregation(s1) = s1', () => {
      const params = CoinSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = CoinSig.keygen(params);
      const coin_params = CoinSig.setup();
      const [coin_sk, coin_pk] = generateCoinSecret(coin_params);
      const coin_id = G.ctx.BIG.randomnum(G.order, G.rngGen);
      const ID = G.ctx.PAIR.G1mul(g1, coin_id);
      const dummyCoin = {
        value: 42,
        ttl: new Date().getTime(),
        v: coin_pk,
        ID: ID,
      };

      const sig = CoinSig.sign(params, sk, dummyCoin);
      const aggregateSig = CoinSig.aggregateSignatures(params, [sig]);

      assert.isTrue(sig[0].equals(aggregateSig[0]));
      assert.isTrue(sig[1].equals(aggregateSig[1]));
    });

    it('Returns null if one of signatures is invalid (different h)', () => {
      const params = CoinSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = CoinSig.keygen(params);

      const coin_params = CoinSig.setup();
      const [coin_sk1, coin_pk1] = generateCoinSecret(coin_params);
      const [coin_sk2, coin_pk2] = generateCoinSecret(coin_params);

      const coin_id1 = G.ctx.BIG.randomnum(G.order, G.rngGen);
      const ID1 = G.ctx.PAIR.G1mul(g1, coin_id1);
      const dummyCoin1 = {
        value: 42,
        ttl: new Date().getTime(),
        v: coin_pk1,
        ID: ID1,
      };

      const coin_id2 = G.ctx.BIG.randomnum(G.order, G.rngGen);
      const ID2 = G.ctx.PAIR.G1mul(g1, coin_id2);
      const dummyCoin2 = {
        value: 42,
        ttl: new Date().getTime(),
        v: coin_pk2,
        ID: ID2,
      };


      const sig1 = CoinSig.sign(params, sk, dummyCoin1);
      const sig2 = CoinSig.sign(params, sk, dummyCoin2);

      const aggregateSig = CoinSig.aggregateSignatures(params, [sig1, sig2]);

      expect(aggregateSig).to.be.a('null');
    });
  });
  describe('Aggregate Verification', () => {
    describe('Public Key Aggregation', () => {
      it('Returns same key if single key is sent', () => {
        const params = CoinSig.setup();
        const [sk, pk] = CoinSig.keygen(params);
        const aPk = CoinSig.aggregatePublicKeys(params, [pk]);
        for (let i = 0; i < pk.length; i++) {
          assert.isTrue(pk[i].equals(aPk[i]));
        }
      });
    });

    describe('Aggregate Verification', () => {
      it('Works for single signature', () => {
        const params = CoinSig.setup();
        const [G, o, g1, g2, e] = params;
        const [sk, pk] = CoinSig.keygen(params);

        const coin_params = CoinSig.setup();
        const [coin_sk, coin_pk] = generateCoinSecret(coin_params);
        const coin_id = G.ctx.BIG.randomnum(G.order, G.rngGen);
        const ID = G.ctx.PAIR.G1mul(g1, coin_id);
        const dummyCoin = {
          value: 42,
          ttl: new Date().getTime(),
          v: coin_pk,
          ID: ID,
        };

        const sig = CoinSig.sign(params, sk, dummyCoin);
        const aggregateSig = CoinSig.aggregateSignatures(params, [sig]);

        assert.isTrue(CoinSig.verifyAggregation(params, [pk], dummyCoin, aggregateSig));
      });

      it('Works for three distinct signatures', () => {
        const params = CoinSig.setup();
        const [G, o, g1, g2, e] = params;
        const [sk, pk] = CoinSig.keygen(params);

        const coin_params = CoinSig.setup();
        const [coin_sk, coin_pk] = generateCoinSecret(coin_params);
        const coin_id = G.ctx.BIG.randomnum(G.order, G.rngGen);
        const ID = G.ctx.PAIR.G1mul(g1, coin_id);
        const dummyCoin = {
          value: 42,
          ttl: new Date().getTime(),
          v: coin_pk,
          ID: ID,
        };

        const coinsToSign = 3;
        const pks = [];
        const signatures = [];

        for (let i = 0; i < coinsToSign; i++) {
          const [sk, pk] = CoinSig.keygen(params);
          pks.push(pk);
          const signature = CoinSig.sign(params, sk, dummyCoin);
          signatures.push(signature);
        }

        const aggregateSignature = CoinSig.aggregateSignatures(params, signatures);

        assert.isTrue(CoinSig.verifyAggregation(params, pks, dummyCoin, aggregateSignature));
      });

      it('Doesn\'t work when one of three signatures is on different coin (but for some reason has same ID)', () => {
        const params = CoinSig.setup();
        const [G, o, g1, g2, e] = params;
        const [sk, pk] = CoinSig.keygen(params);

        const coin_params = CoinSig.setup();
        const [coin_sk, coin_pk] = generateCoinSecret(coin_params);
        const coin_id = G.ctx.BIG.randomnum(G.order, G.rngGen);
        const ID = G.ctx.PAIR.G1mul(g1, coin_id);
        const dummyCoin = {
          value: 42,
          ttl: new Date().getTime(),
          v: coin_pk,
          ID: ID,
        };

        const coinsToSign = 2;
        const pks = [];
        const signatures = [];

        for (let i = 0; i < coinsToSign; i++) {
          const [sk, pk] = CoinSig.keygen(params);
          pks.push(pk);
          const signature = CoinSig.sign(params, sk, dummyCoin);
          signatures.push(signature);
        }

        const [another_coin_sk, another_coin_pk] = generateCoinSecret(coin_params);
        const anotherCoin = {
          value: 42,
          ttl: new Date().getTime(),
          v: another_coin_pk,
          ID: ID,
        };

        const [skm, pkm] = CoinSig.keygen(params);
        pks.push(pkm);
        const maliciousSignature = CoinSig.sign(params, skm, anotherCoin);
        signatures.push(maliciousSignature);

        const aggregateSignature = CoinSig.aggregateSignatures(params, signatures);
        assert.isNotTrue(CoinSig.verifyAggregation(params, pks, dummyCoin, aggregateSignature));
      });
    });
  });

  describe('Blind Signature', () => {
    it('Can produce a blind signature and successfully verify it after decryption', () => {
      const params = CoinSig.setup();
      const [G, o, g1, g2, e] = params;

      const value = 42;
      const coin_id = G.ctx.BIG.randomnum(G.order, G.rngGen);
      // first we need to create a coin to sign
      const pkBytes_client = [];
      const skBytes_client = [];
      const sk_client = G.ctx.BIG.randomnum(o, G.rngGen);
      const pk_client = g1.mul(sk_client);
      sk_client.toBytes(skBytes_client);
      pk_client.toBytes(pkBytes_client);

      const coin_pk_bytes = [];
      const coin_sk = G.ctx.BIG.randomnum(G.order, G.rngGen);
      const coin_pk = G.ctx.PAIR.G2mul(g2, coin_sk);
      coin_pk.toBytes(coin_pk_bytes);


      const sk_issuer_bytes = [];
      const sk_issuer = G.ctx.BIG.randomnum(o, G.rngGen);
      const pk_issuer = g1.mul(sk_issuer);
      sk_issuer.toBytes(sk_issuer_bytes);

      const [ElGamalSK, ElGamalPK] = ElGamal.keygen(params);

      const issuedCoin = getIssuedCoin(coin_pk_bytes, value, pkBytes_client, sk_issuer_bytes);
      const signingCoin = getSigningCoin(issuedCoin, ElGamalPK, coin_id, coin_sk, skBytes_client);

      const [sk, pk] = CoinSig.keygen(params);
      const [h, enc_sig] = CoinSig.mixedSignCoin(params, sk, signingCoin, ElGamalPK);

      const sig = ElGamal.decrypt(params, ElGamalSK, enc_sig);

      const signature = [h, sig];

      const pkX = G.ctx.PAIR.G2mul(pk[4], coin_sk);
      assert.isTrue(CoinSig.verifyMixedBlindSign(params, pk, signingCoin, [h, sig], coin_id, pkX));
    });
  });
});
