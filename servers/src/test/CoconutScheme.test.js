import { describe, it } from 'mocha';
import { expect, assert } from 'chai';
import { ctx } from '../globalConfig';
import CredSig from '../CredSig';
import BpGroup from '../BpGroup';
import { hashToBIG, hashToPointOnCurve, prepareProofOfSecret, verifyProofOfSecret, fromBytesProof,
  prepareProofOfSecret_Auth, verifyProofOfSecret_Auth, fromBytesProof_Auth, fromBytesMPVP } from '../auxiliary';
import ElGamal from '../ElGamal';
import { getSigningCred, verifySignRequest } from '../SigningCred';
import { getIssuedCred, verifyCredSignature } from '../IssuedCred';
import { getBytesProof, getBytesProof_Auth, getBytesMPVP } from '../CredRequest';

const generateCredSecret = (params) => {
  const [G, o, g1, g2, e, h1] = params;
  const m = ctx.BIG.randomnum(G.order, G.rngGen);
  const pk = ctx.PAIR.G1mul(g1, m);

  // random blindling factor o_blind
  const o_blind = ctx.BIG.randomnum(G.order, G.rngGen);
  const h_blind = ctx.PAIR.G1mul(h1, o_blind);

  pk.add(h_blind);
  pk.affine();

  const sk = {
    m: m,
    o: o_blind,
  };

  return [sk, pk];
};

describe('Coconut Scheme:', () => {
  describe('Setup:', () => {
    const params = CredSig.setup();
    const [G, o, g1, g2, e] = params;

    it('Returns BpGroup Object', () => {
      assert.isNotNull(G);
      assert.isTrue(G instanceof(BpGroup));
    });

    it('Returns Group Order', () => {
      assert.isNotNull(o);
      assert.isTrue(o instanceof(G.ctx.BIG));
    });

    it('Returns Gen1', () => {
      assert.isNotNull(g1);
      assert.isTrue(g1 instanceof(G.ctx.ECP));
    });

    it('Returns Gen2', () => {
      assert.isNotNull(g2);
      assert.isTrue(g2 instanceof(G.ctx.ECP2));
    });

    it('Returns Pair function', () => {
      assert.isNotNull(e);
      assert.isTrue(e instanceof(Function));
    });
  });

  describe('Keygen', () => {
    const params = CredSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = CredSig.keygen(params);

    const [x, y] = sk;
    const [g, X, Y] = pk;

    it('Returns Secret Key (x0, x1, x2, x3, x4)', () => {
      assert.isTrue(x instanceof(G.ctx.BIG));
      assert.isTrue(y instanceof(G.ctx.BIG));
    });

    describe('Returns Valid Private Key (g, X, Y)', () => {
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

  describe('NIZK proof of secret for the commitment (sent to issuer)', () => {
    it('Verified proofOfSecret_Issuer', () => {
      const params = CredSig.setup();
      const [G, o, g1, g2, e] = params;
      const [cred_sks, cred_pk] = generateCredSecret(params);

      const issuingServerStr = 'issuer';
      const secretProof = prepareProofOfSecret(params, cred_sks, issuingServerStr);
      const proof_bytes = getBytesProof(secretProof); // EDIT: FIX to c rm ro

      const proof = fromBytesProof(proof_bytes);
      assert.isTrue(verifyProofOfSecret(params, cred_pk, proof, issuingServerStr));
    });
  });

  describe('NIZK proof of secret for the encryption of the commitment (sent to signing authorities)', () => {
    it('Verified proofOfSecret_Auth', () => {
      const params = CredSig.setup();
      const [G, o, g1, g2, e] = params;
      const [cred_sks, cred_pk] = generateCredSecret(params);
      const [sk_elgamal, pk_elgamal] = ElGamal.keygen(params);

      const credStr = cred_pk.toString() + pk_elgamal.toString();
  
      const h = hashToPointOnCurve(credStr);
    
      const [a, b, k] = ElGamal.encrypt(params, pk_elgamal, cred_sks.m, h);
    
      const enc_sk = [a, b];

      // const signingAuthStr = 'signing authority';
      // const secretProof = prepareProofOfSecret_Auth(params, h, cred_sks, sk_elgamal, k, signingAuthStr);
      const secretProof = prepareProofOfSecret_Auth(params, h, cred_sks, sk_elgamal, k);
      const proof_bytes = getBytesProof_Auth(secretProof);

      const proof = fromBytesProof_Auth(proof_bytes);
      // assert.isTrue(verifyProofOfSecret_Auth(params, h, cred_pk, pk_elgamal, enc_sk, proof, signingAuthStr));
      assert.isTrue(verifyProofOfSecret_Auth(params, h, cred_pk, pk_elgamal, enc_sk, proof));
    });
  });

  // [h, sig = (x + m*y) * h]
  describe('Sign', () => {
    it('For signature(h, sig): sig = (x + m*y) * h', () => {
      const params = CredSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = CredSig.keygen(params);
      const [x, y] = sk;

      const cred_params = CredSig.setup();
      // create commitment
      const [cred_sks, cred_pk] = generateCredSecret(cred_params);
      const cred_sk = cred_sks.m;

      const signature = CredSig.sign(params, sk, cred_sk, cred_pk);
      const [h, sig] = signature;

      const m = new G.ctx.BIG(cred_sk);

      // calculate t1 = (y * m) mod p
      const t1 = G.ctx.BIG.mul(y, m);
      t1.mod(o);
      // x + t1
      const K = new G.ctx.BIG(t1);
      K.add(x);
      // K = (x + m*y) mod p
      K.mod(o);

      const sig_test = G.ctx.PAIR.G1mul(h, K);

      assert.isTrue(sig.equals(sig_test));
    });
  });

  describe('Verify', () => {
    const params = CredSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = CredSig.keygen(params);
    const cred_params = CredSig.setup();
    const [cred_sks, cred_pk] = generateCredSecret(cred_params);
    const cred_sk = cred_sks.m;

    const sigma = CredSig.sign(params, sk, cred_sk, cred_pk);


    it('Successful verification of original credential', () => {
      assert.isTrue(CredSig.verify(params, pk, cred_sk, sigma));
    });

    it('Failed verification for credential with different secret', () => {
      const [new_cred_sks, new_cred_pk] = generateCredSecret(cred_params);
      const new_cred_sk = new_cred_sks.m;
      const testCred = new_cred_sk;
      assert.isNotTrue(CredSig.verify(params, pk, testCred, sigma));
    });
  });

  describe('Randomize', () => {
    const params = CredSig.setup();
    const [G, o, g1, g2, e] = params;
    const [sk, pk] = CredSig.keygen(params);
    const cred_params = CredSig.setup();
    const [cred_sks, cred_pk] = generateCredSecret(cred_params);
    const cred_sk = cred_sks.m;

    let sigma = CredSig.sign(params, sk, cred_sk, cred_pk);
    sigma = CredSig.randomize(params, sigma);

    it('Successful verification for original credential with randomized signature', () => {
      assert.isTrue(CredSig.verify(params, pk, cred_sk, sigma));
    });
  });

  describe('Aggregate', () => {
    it('Aggregation(s1) = s1', () => {
      const params = CredSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = CredSig.keygen(params);
      const cred_params = CredSig.setup();
      const [cred_sks, cred_pk] = generateCredSecret(cred_params);
      const cred_sk = cred_sks.m;

      const sigma = CredSig.sign(params, sk, cred_sk, cred_pk);
      const aggregateSig = CredSig.aggregateSignatures(params, [sigma]);

      assert.isTrue(sigma[0].equals(aggregateSig[0]));
      assert.isTrue(sigma[1].equals(aggregateSig[1]));
    });

    it('Returns null if one of signatures is invalid (different h)', () => {
      const params = CredSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk, pk] = CredSig.keygen(params);

      const cred_params = CredSig.setup();
      const [cred_sks1, cred_pk1] = generateCredSecret(cred_params);
      const cred_sk1 = cred_sks1.m;
      const [cred_sks2, cred_pk2] = generateCredSecret(cred_params);
      const cred_sk2 = cred_sks2.m;

      const sigma1 = CredSig.sign(params, sk, cred_sk1, cred_pk1);
      const sigma2 = CredSig.sign(params, sk, cred_sk2, cred_pk2);

      const aggregateSig = CredSig.aggregateSignatures(params, [sigma1, sigma2]);

      expect(aggregateSig).to.be.a('null');
    });
  });

  describe('Aggregate Verification', () => {
    describe('Public Key Aggregation', () => {
      it('Returns same key if single key is sent', () => {
        const params = CredSig.setup();
        const [sk, pk] = CredSig.keygen(params);
        const aPk = CredSig.aggregatePublicKeys_array(params, [pk]);
        for (let i = 0; i < pk.length; i++) {
          assert.isTrue(pk[i].equals(aPk[i]));
        }
      });
    });

    describe('Aggregate Verification', () => {
      it('Works for single signature', () => {
        const params = CredSig.setup();
        const [G, o, g1, g2, e] = params;
        const [sk, pk] = CredSig.keygen(params);
        const cred_params = CredSig.setup();
        const [cred_sks, cred_pk] = generateCredSecret(cred_params);
        const cred_sk = cred_sks.m;

        const sigma = CredSig.sign(params, sk, cred_sk, cred_pk);
        const aggregateSig = CredSig.aggregateSignatures(params, [sigma]);

        assert.isTrue(CredSig.verifyAggregation(params, [pk], cred_sk, aggregateSig));
      });

      it('Works for three distinct signatures', () => {
        const params = CredSig.setup();
        const [G, o, g1, g2, e] = params;
        const [sk, pk] = CredSig.keygen(params);
        const cred_params = CredSig.setup(); // EDIT:
        const [cred_sks, cred_pk] = generateCredSecret(cred_params);
        const cred_sk = cred_sks.m;

        const credsToSign = 3;
        const pks = [];
        const signatures = [];

        for (let i = 0; i < credsToSign; i++) {
          const [sk, pk] = CredSig.keygen(params);
          pks.push(pk);
          const signature = CredSig.sign(params, sk, cred_sk, cred_pk);
          signatures.push(signature);
        }

        const aggregateSignature = CredSig.aggregateSignatures(params, signatures);

        assert.isTrue(CredSig.verifyAggregation(params, pks, cred_sk, aggregateSignature));
      });

      it('Doesn\'t work when one of three signatures is on different credential', () => {
        const params = CredSig.setup();
        const [G, o, g1, g2, e] = params;
        const [sk, pk] = CredSig.keygen(params);
        const cred_params = CredSig.setup();
        const [cred_sks, cred_pk] = generateCredSecret(cred_params);
        const cred_sk = cred_sks.m;

        const credsToSign = 2;
        const pks = [];
        const signatures = [];

        for (let i = 0; i < credsToSign; i++) {
          const [sk, pk] = CredSig.keygen(params);
          pks.push(pk);
          const signature = CredSig.sign(params, sk, cred_sk, cred_pk);
          signatures.push(signature);
        }

        const [another_cred_sks, another_cred_pk] = generateCredSecret(cred_params);
        const another_cred_sk = another_cred_sks.m;

        const [skm, pkm] = CredSig.keygen(params);
        pks.push(pkm);
        const maliciousSignature = CredSig.sign(params, skm, another_cred_sk, another_cred_pk);
        signatures.push(maliciousSignature);

        const aggregateSignature = CredSig.aggregateSignatures(params, signatures);
        assert.isNotTrue(CredSig.verifyAggregation(params, pks, cred_sk, aggregateSignature));
      });
    });
  });

  describe('Full Coconut Scheme', () => {
    const params = CredSig.setup();
    const [G, o, g1, g2, e] = params;

    // first we need to create a cred to sign
    const cred_params = CredSig.setup(); // EDIT:
    const [cred_sks, cred_pk] = generateCredSecret(cred_params);
    const cred_sk = cred_sks.m;
    const cred_pk_bytes = [];
    cred_pk.toBytes(cred_pk_bytes);

    // get client key pair
    const pkBytes_client = [];
    const skBytes_client = [];
    const sk_client = G.ctx.BIG.randomnum(o, G.rngGen);
    const pk_client = g1.mul(sk_client);
    sk_client.toBytes(skBytes_client);
    pk_client.toBytes(pkBytes_client);

    const sk_issuer_bytes = [];
    const pk_issuer_bytes = [];
    const sk_issuer = G.ctx.BIG.randomnum(o, G.rngGen);
    const pk_issuer = g1.mul(sk_issuer);
    sk_issuer.toBytes(sk_issuer_bytes);
    pk_issuer.toBytes(pk_issuer_bytes);

    const [ElGamalSK, ElGamalPK] = ElGamal.keygen(params);

    // PREPARE_BLIND_SIGN: issuer sign credential commitment | return: pk_cred_bytes, pk_client_bytes, issuedCredSig
    const issuedCred = getIssuedCred(cred_pk_bytes, pkBytes_client, sk_issuer_bytes);
    it('Credential commitment verified by issuer', () => {
      assert.isTrue(verifyCredSignature(issuedCred, pk_issuer_bytes));
    });

    // PREPARE_BLIND_SIGN: client prepare credential to be signed by authorities
    const signingCred = getSigningCred(issuedCred, ElGamalPK, cred_sk, skBytes_client);
    it('Credential sign request (signatures by issuer and client) verified by signing authority', () => {
      assert.isTrue(verifySignRequest(signingCred, pk_issuer_bytes));
    });

    // BLIND_SIGN: authority signs the credential
    const [sk, pk] = CredSig.keygen(params);
    const [h, enc_sig] = CredSig.mixedSignCred(params, sk, signingCred);

    // UNBLIND: client decrypts signature
    const sig = ElGamal.decrypt(params, ElGamalSK, enc_sig);

    // RANDOMIZE: client randomizes signature
    let sigma = [h, sig];
    sigma = CredSig.randomize(params, sigma);

    // SHOW_BLIND_SIGN: client prepares credential proofs
    const petitionID = 'e-petition';
    it('Aw/kappa verified', () => {
      const gs = hashToPointOnCurve(petitionID);
      const t = ctx.BIG.randomnum(G.order, G.rngGen);
      // kappa = t*g2 + aX + m*aY :
      const kappa = ctx.PAIR.G2mul(g2, t);      // t*g2
      const aX = pk[1];                         // aX
      const aY = pk[2];                         // aY
      const pkY = ctx.PAIR.G2mul(aY, cred_sk);  // m*Y
      kappa.add(aX);
      kappa.add(pkY);
      kappa.affine();

      const wm = ctx.BIG.randomnum(G.order, G.rngGen);
      const wt = ctx.BIG.randomnum(G.order, G.rngGen);
      const Aw = ctx.PAIR.G2mul(g2, wt);
      Aw.add(aX);
      const pkYw = ctx.PAIR.G2mul(aY, wm);
      Aw.add(pkYw);
      Aw.affine();

      const c = hashToBIG(g2.toString() + Aw.toString());
      const m_cpy = new ctx.BIG(cred_sk);
      m_cpy.mod(o);
      const t1 = ctx.BIG.mul(m_cpy, c); // produces DBIG
      const t2 = t1.mod(o); // but this gives BIG back
      const rm = new ctx.BIG(wm);
      rm.sub(t2);
      rm.add(o); // to ensure positive result EDIT: REMOVE?
      rm.mod(o);
      const t_cpy = new ctx.BIG(t);
      t_cpy.mod(o);
      const t3 = ctx.BIG.mul(t_cpy, c); // produces DBIG
      const t4 = t3.mod(o); // but this gives BIG back
      const rt = new ctx.BIG(wt);
      rt.sub(t4);
      rt.add(o); // to ensure positive result
      rt.mod(o);

      const Aw2 = ctx.PAIR.G2mul(kappa, c);
      const temp1 = ctx.PAIR.G2mul(g2, rt);
      Aw2.add(temp1);
      Aw2.add(aX);
      const temp2 = ctx.PAIR.G2mul(aX, c);
      Aw2.sub(temp2);
      const temp3 = ctx.PAIR.G2mul(aY, rm);
      Aw2.add(temp3);
      Aw2.affine();

      const expr = Aw.equals(Aw2);

      assert.isTrue(expr);
    });

    it('Bw/nu verified', () => {
      const t = ctx.BIG.randomnum(G.order, G.rngGen);
      const nu = ctx.PAIR.G1mul(h, t);
      const wt = ctx.BIG.randomnum(G.order, G.rngGen);
      const Bw = ctx.PAIR.G1mul(h, wt);
      Bw.affine();

      const c = hashToBIG(g1.toString() + Bw.toString());
      const t_cpy = new ctx.BIG(t);
      t_cpy.mod(o);
      const t3 = ctx.BIG.mul(t_cpy, c); // produces DBIG
      const t4 = t3.mod(o); // but this gives BIG back
      const rt = new ctx.BIG(wt);
      rt.sub(t4);
      rt.add(o); // to ensure positive result
      rt.mod(o);

      const Bw2 = ctx.PAIR.G1mul(nu, c);
      const temp4 = ctx.PAIR.G1mul(h, rt);
      Bw2.add(temp4);
      Bw2.affine();

      const expr = Bw.equals(Bw2);

      assert.isTrue(expr);
    });

    it('Cw/zeta verified', () => {
      const gs = hashToPointOnCurve(petitionID);
      const zeta = ctx.PAIR.G1mul(gs, cred_sk);
      const wm = ctx.BIG.randomnum(G.order, G.rngGen);
      const Cw = ctx.PAIR.G1mul(gs, wm);
      Cw.affine();

      const c = hashToBIG(g1.toString() + Cw.toString());
      const m_cpy = new ctx.BIG(cred_sk);
      m_cpy.mod(o);
      const t1 = ctx.BIG.mul(m_cpy, c); // produces DBIG
      const t2 = t1.mod(o); // but this gives BIG back
      const rm = new ctx.BIG(wm);
      rm.sub(t2);
      rm.add(o); // to ensure positive result EDIT: REMOVE?
      rm.mod(o);

      const Cw2 = ctx.PAIR.G1mul(gs, rm);
      const temp5 = ctx.PAIR.G1mul(zeta, c);
      Cw2.add(temp5);
      Cw2.affine();

      const expr = Cw.equals(Cw2);

      assert.isTrue(expr);
    });
    
    // BLIND_VERIFY: petitionOwner/issuer verifies credential
    it('Credential shown by client is verified', () => {
      const petitionOwner = 'petitionOwner public key';
      const MPCP_output = CredSig.make_proof_credentials_petition(params, pk, sigma, cred_sk, petitionOwner, petitionID);
      assert.isTrue(CredSig.verify_proof_credentials_petition(params, pk, sigma, MPCP_output, petitionOwner, petitionID));
    });
  });

  describe('Threshold decryption', () => {
    describe('Make proof vote petition', () => {
      const params = CredSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk_elgamal, pk_elgamal] = ElGamal.keygen(params);
  
      it('Verified proofOfSecret for vote = 1 or = 0', () => {
        const MPVP_output = CredSig.make_proof_vote_petition(params, pk_elgamal, 1);
        const proof_bytes = getBytesMPVP(MPVP_output);
  
        const MPVP_output_sent = fromBytesMPVP(proof_bytes);
        assert.isTrue(CredSig.verify_proof_vote_petition(params, pk_elgamal, MPVP_output_sent));
      });
  
      it('Fails proofOfSecret for vote != 1 and != 0', () => {
        const MPVP_output = CredSig.make_proof_vote_petition(params, pk_elgamal, 5);
        const proof_bytes = getBytesMPVP(MPVP_output);
  
        const MPVP_output_sent = fromBytesMPVP(proof_bytes);
        assert.isFalse(CredSig.verify_proof_vote_petition(params, pk_elgamal, MPVP_output_sent));
      });
    });
    describe('Aggregate public key encryption and aggregate secret key decryption', () => {

      const params = CredSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk1, pk1] = ElGamal.keygen(params);
      const [sk2, pk2] = ElGamal.keygen(params);
      const [sk3, pk3] = ElGamal.keygen(params);
      const aPk = CredSig.aggregateElGamalPublicKeys(params, [pk1, pk2, pk3]);
      const aSk = new ctx.BIG(sk1);
      aSk.add(sk2);
      aSk.add(sk3);
      aSk.mod(o);

      it('Works for m < max', () => {
        const vote = new ctx.BIG(2);
        const h = hashToPointOnCurve('Threshold decryption');
        const [a, b, k] = ElGamal.encrypt(params, aPk, vote, h);

        const hdec = ElGamal.decrypt(params, aSk, [a, b]);
        const dec = ElGamal.logh(params, hdec, h, 100);
        let expr1 = true;
        let expr2 = true;
        if (dec === false) {
          expr1 = false;
        } else {
          expr2 = ctx.BIG.comp(vote, dec) === 0;
        }
        assert.isTrue(expr1 && expr2);
      });

      it('Returns false for m > max or m not found', () => {
        const vote = new ctx.BIG(200);
        const h = hashToPointOnCurve('Threshold decryption');
        const [a, b, k] = ElGamal.encrypt(params, aPk, vote, h);

        const hdec = ElGamal.decrypt(params, aSk, [a, b]);
        const dec = ElGamal.logh(params, hdec, h, 100);
        let expr1 = true;
        let expr2 = true;
        if (dec === false) {
          expr1 = false;
        } else {
          expr2 = ctx.BIG.comp(vote, dec) === 0;
        }
        assert.isFalse(expr1 && expr2);
      });
    });

    describe('Aggregate public key (3 keys) encryption and 3 threshold decryptions', () => {
      it('Works for 3 threshold decryptions of 1 vote (random number)', () => {
        const params = CredSig.setup();
        const [G, o, g1, g2, e] = params;
        const [sk1, pk1] = ElGamal.keygen(params);
        const [sk2, pk2] = ElGamal.keygen(params);
        const [sk3, pk3] = ElGamal.keygen(params);
        const pks = [pk1, pk2, pk3];
        const aPk = CredSig.aggregateElGamalPublicKeys(params, pks);
        
        const vote = new ctx.BIG(2);
        const h = hashToPointOnCurve('Threshold decryption');
        const [a, b, k] = ElGamal.encrypt(params, aPk, vote, h);
        
        const sks = [sk1, sk2, sk3];
        let hdec = b;
        let dec;
        for (let i = (sks.length - 1); i >= 0; i--) {
          hdec = ElGamal.decrypt(params, sks[i], [a, hdec]);
          if (i === 0) {
            dec = ElGamal.logh(params, hdec, h, 100);
          }
        }

        const expr = ctx.BIG.comp(vote, dec) === 0;
        assert.isTrue(expr);
      });

      it('Works for 3 threshold decryptions of added votes', () => {
        const params = CredSig.setup();
        const [G, o, g1, g2, e] = params;
        const [sk1, pk1] = ElGamal.keygen(params);
        const [sk2, pk2] = ElGamal.keygen(params);
        const [sk3, pk3] = ElGamal.keygen(params);
        const pks = [pk1, pk2, pk3];
        const aPk = CredSig.aggregateElGamalPublicKeys(params, pks);
        const h = hashToPointOnCurve('Threshold decryption');
        
        const votes = [1, 1, 1];
        const big_votes = [];
        big_votes[0] = new ctx.BIG(votes[0]);
        const [agg_a, agg_b, k] = ElGamal.encrypt(params, aPk, big_votes[0], h);
        for (let i = 1; i < votes.length; i++) {
          big_votes[i] = new ctx.BIG(votes[i]);
          const [a, b, k] = ElGamal.encrypt(params, aPk, big_votes[i], h);
          agg_a.add(a);
          agg_b.add(b);
        }
        agg_a.affine();
        agg_b.affine();
        
        const sks = [sk1, sk2, sk3];
        
        let hdec = agg_b;
        let dec;
        for (let i = (sks.length - 1); i >= 0; i--) {
          hdec = ElGamal.decrypt(params, sks[i], [agg_a, hdec]);
          if (i === 0) {
            dec = ElGamal.logh(params, hdec, h, 100);
          }
        }

        const vote = new ctx.BIG(3);
        const expr = ctx.BIG.comp(vote, dec) === 0;
        assert.isTrue(expr);
      });


      const params = CredSig.setup();
      const [G, o, g1, g2, e] = params;
      const [sk1, pk1] = ElGamal.keygen(params);
      const [sk2, pk2] = ElGamal.keygen(params);
      const [sk3, pk3] = ElGamal.keygen(params);
      const pks = [pk1, pk2, pk3];
      const aPk = CredSig.aggregateElGamalPublicKeys(params, pks);
      const h = hashToPointOnCurve('Threshold decryption');
      
      // const votes = [0, 1, 1, 0, 1, 0, 1]; // 3 v0, 4 v1
      const votes = [0, 1, 1, 0, 1, 0, 1,1,0,0,0,1,1,0,1,0,1,1,1,1,0,0,0]; // 11 v0, 12 v1
      const big_votes = [];
      big_votes[0] = new ctx.BIG(votes[0]);
      let V0;
      let V1;
      if (votes[0] === 1) {
        // return [a, b, k]
        V0 = ElGamal.encrypt(params, aPk, new ctx.BIG(0), h);
        V1 = ElGamal.encrypt(params, aPk, new ctx.BIG(1), h);
      } else {
        V0 = ElGamal.encrypt(params, aPk, new ctx.BIG(1), h);
        V1 = ElGamal.encrypt(params, aPk, new ctx.BIG(0), h);
      }
      const [V0_agg_a, V0_agg_b, kv0] = V0;
      const [V1_agg_a, V1_agg_b, kv1] = V1;

      let V0_temp;
      let V1_temp;
      for (let i = 1; i < votes.length; i++) {
        if (votes[i] === 1) {
          // return [a, b, k]
          V0_temp = ElGamal.encrypt(params, aPk, new ctx.BIG(0), h);
          V1_temp = ElGamal.encrypt(params, aPk, new ctx.BIG(1), h);
        } else {
          V0_temp = ElGamal.encrypt(params, aPk, new ctx.BIG(1), h);
          V1_temp = ElGamal.encrypt(params, aPk, new ctx.BIG(0), h);
        } // end if

        V0_agg_a.add(V0_temp[0]);
        V0_agg_b.add(V0_temp[1]);

        V1_agg_a.add(V1_temp[0]);
        V1_agg_b.add(V1_temp[1]);
      } // end for

      V0_agg_a.affine();
      V0_agg_b.affine();
      V1_agg_a.affine();
      V1_agg_b.affine();
      
      const sks = [sk1, sk2, sk3];
      
      // V0:
      let hdecV0 = V0_agg_b;
      let decV0;
      for (let i = (sks.length - 1); i >= 0; i--) {
        hdecV0 = ElGamal.decrypt(params, sks[i], [V0_agg_a, hdecV0]);
        if (i === 0) {
          decV0 = ElGamal.logh(params, hdecV0, h, 100);
        }
      }
      
      it('Works for V0 decryptions', () => {
        const vote = new ctx.BIG(11);
        const expr = ctx.BIG.comp(vote, decV0) === 0;
        assert.isTrue(expr);
      });

      // V1:
      let hdecV1 = V1_agg_b;
      let decV1;
      for (let i = (sks.length - 1); i >= 0; i--) {
        hdecV1 = ElGamal.decrypt(params, sks[i], [V1_agg_a, hdecV1]);
        if (i === 0) {
          decV1 = ElGamal.logh(params, hdecV1, h, 100);
        }
      }
      
      it('Works for V1 decryptions', () => {
        const vote = new ctx.BIG(12);
        const expr = ctx.BIG.comp(vote, decV1) === 0;
        assert.isTrue(expr);
      });

      it('Works to ouput the results', () => {
        const no_string = decV0.toString();
        const yes_string = decV1.toString();
        console.log(`Number of "no" votes: ${parseInt(no_string, 16)}`);
        console.log(`Number of "yes" votes: ${parseInt(yes_string, 16)}`);
      });
    });

  });
});
