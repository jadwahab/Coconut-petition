import { hashToPointOnCurve } from './auxiliary';
import { ctx, params } from './globalConfig';
import ElGamal from './ElGamal';

export const getSigningCred = (issuedCred, ElGamalPK, cred_sk, sk_client_bytes) => {
  const [G, o, g1, g2, e] = params;

  const reducer = (acc, cur) => acc + cur;

  const credStr =
    issuedCred.pk_client_bytes.reduce(reducer) + // client's key
    issuedCred.pk_cred_bytes.reduce(reducer) + // cred's pk
    issuedCred.issuedCredSig[0].reduce(reducer) +
    issuedCred.issuedCredSig[1].reduce(reducer);

  const h = hashToPointOnCurve(credStr);

  const [a, b, k] = ElGamal.encrypt(params, ElGamalPK, cred_sk, h);

  const enc_sk = [a, b];

  const sk_a_bytes = [];
  const sk_b_bytes = [];

  enc_sk[0].toBytes(sk_a_bytes);
  enc_sk[1].toBytes(sk_b_bytes);

  const enc_sk_bytes = [sk_a_bytes, sk_b_bytes];

  // beginning of the string will be identical so just append our ciphertext
  const requestStr = credStr +
    enc_sk_bytes[0].reduce(reducer) +
    enc_sk_bytes[1].reduce(reducer);

  const sha = ctx.ECDH.HASH_TYPE;
  const C = [];
  const D = [];

  ctx.ECDH.ECPSP_DSA(sha, G.rngGen, sk_client_bytes, requestStr, C, D);
  const requestSig = [C, D];

  return {
    pk_cred_bytes: issuedCred.pk_cred_bytes,
    pk_client_bytes: issuedCred.pk_client_bytes,
    issuedCredSig: issuedCred.issuedCredSig,
    enc_sk_bytes: enc_sk_bytes,
    requestSig: requestSig,
  };

  // Representation:
  /*
  { { v (commitment)
      pk_c
    }signed by issuer
    E[h^x]
  }signed by client
 */
};

export const verifySignRequest = (signingCred, issuerPK) => {
  if (issuerPK == null) {
    return false;
  }

  // first verify 'internal' signature of the issuer that such cred was issued and wasn't modified
  const sha = ctx.ECDH.HASH_TYPE;
  const [C1, D1] = signingCred.issuedCredSig;

  const reducer = (acc, cur) => acc + cur;

  const credStr =
    signingCred.pk_client_bytes.reduce(reducer) + // client's key
    signingCred.pk_cred_bytes.reduce(reducer); // cred's pk

  if (ctx.ECDH.ECPVP_DSA(sha, issuerPK, credStr, C1, D1) !== 0) {
    return false;
  }

  const requestStr = credStr +
    C1.reduce(reducer) +
    D1.reduce(reducer) +
    signingCred.enc_sk_bytes[0].reduce(reducer) +
    signingCred.enc_sk_bytes[1].reduce(reducer);

  const [C2, D2] = signingCred.requestSig;

  return ctx.ECDH.ECPVP_DSA(sha, signingCred.pk_client_bytes, requestStr, C2, D2) === 0;
};
