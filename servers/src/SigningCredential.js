import { hashToPointOnCurve } from './auxiliary';
import { ctx, params } from './globalConfig';
import ElGamal from './ElGamal';

export const getSigningCredential = (issuedCoin, ElGamalPK, coin_sk, sk_client_bytes) => {
  const [G, o, g1, g2, e] = params;

  const reducer = (acc, cur) => acc + cur;

  const coinStr =
    issuedCoin.pk_client_bytes.reduce(reducer) + // client's key
    issuedCoin.pk_coin_bytes.reduce(reducer) + // coin's pk
    issuedCoin.issuedCoinSig[0].reduce(reducer) +
    issuedCoin.issuedCoinSig[1].reduce(reducer);

  const h = hashToPointOnCurve(coinStr);

  const [a, b, k] = ElGamal.encrypt(params, ElGamalPK, coin_sk, h);

  const enc_sk = [a, b];

  const sk_a_bytes = [];
  const sk_b_bytes = [];

  enc_sk[0].toBytes(sk_a_bytes);
  enc_sk[1].toBytes(sk_b_bytes);

  const enc_sk_bytes = [sk_a_bytes, sk_b_bytes];

  // beginning of the string will be identical so just append our ciphertext
  const requestStr = coinStr +
    enc_sk_bytes[0].reduce(reducer) +
    enc_sk_bytes[1].reduce(reducer);

  const sha = ctx.ECDH.HASH_TYPE;
  const C = [];
  const D = [];

  ctx.ECDH.ECPSP_DSA(sha, G.rngGen, sk_client_bytes, requestStr, C, D);
  const requestSig = [C, D];

  return {
    pk_coin_bytes: issuedCoin.pk_coin_bytes,
    pk_client_bytes: issuedCoin.pk_client_bytes,
    issuedCoinSig: issuedCoin.issuedCoinSig,
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

export const verifySignRequest = (signingCoin, issuerPK) => {
  if (issuerPK == null) {
    return false;
  }

  // first verify 'internal' signature of the issuer that such coin was issued and wasn't modified
  const sha = ctx.ECDH.HASH_TYPE;
  const [C1, D1] = signingCoin.issuedCoinSig;

  const reducer = (acc, cur) => acc + cur;

  const coinStr =
    signingCoin.pk_client_bytes.reduce(reducer) + // client's key
    signingCoin.pk_coin_bytes.reduce(reducer); // coin's pk

  if (ctx.ECDH.ECPVP_DSA(sha, issuerPK, coinStr, C1, D1) !== 0) {
    return false;
  }

  const requestStr = coinStr +
    C1.reduce(reducer) +
    D1.reduce(reducer) +
    signingCoin.enc_sk_bytes[0].reduce(reducer) +
    signingCoin.enc_sk_bytes[1].reduce(reducer);

  const [C2, D2] = signingCoin.requestSig;

  return ctx.ECDH.ECPVP_DSA(sha, signingCoin.pk_client_bytes, requestStr, C2, D2) === 0;
};
