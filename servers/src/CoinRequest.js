import { ctx, params } from './globalConfig';
import { prepareProofOfSecret, verifyProofOfSecret, fromBytesProof } from './auxiliary';

const getBytesProof = (proof) => {
  const [W, cm, r] = proof;
  const bytesW = [];
  const bytesCm = [];
  const bytesR = [];
  W.toBytes(bytesW);
  cm.toBytes(bytesCm);
  r.toBytes(bytesR);

  return [bytesW, bytesCm, bytesR];
};

export const getCoinRequestObject = (
  sk_coin, // to generate proof of secret
  pk_coin, // part of the coin
  // value, // part of the coin
  pk_client_bytes, // part of the coin
  sk_client, // to sign the request
  issuingServer, // to include in the proof of secret, it just has to be some string
) => {
  const [G, o, g1, g2, e] = params;

  const pk_coin_bytes = [];
  pk_coin.toBytes(pk_coin_bytes);
  const secretProof = prepareProofOfSecret(params, sk_coin, issuingServer);
  const proof_bytes = getBytesProof(secretProof);

  const [bytesW, bytesCm, bytesR] = proof_bytes; // expand to include in our signature

  // we just need to have same representation of both the string on both ends
  // so for bytes representations, just add up the bytes (it is quicker than concating all elements)
  const reducer = (acc, cur) => acc + cur;

  const requestStr =
    pk_client_bytes.reduce(reducer) + // client's key
    // value.toString() + // coin's value
    pk_coin_bytes.reduce(reducer) + // coin's pk
    bytesW.reduce(reducer) + // part of proof of coin's secret
    bytesCm.reduce(reducer) + // part of proof of coin's secret
    bytesR.reduce(reducer); // part of proof of coin's secret

  const sha = ctx.ECDH.HASH_TYPE;

  const C = [];
  const D = [];

  // to 'authorise' the request
  ctx.ECDH.ECPSP_DSA(sha, G.rngGen, sk_client, requestStr, C, D);
  const requestSig = [C, D];
  return {
    pk_coin_bytes: pk_coin_bytes,
    proof_bytes: proof_bytes,
    // value: value,
    pk_client_bytes: pk_client_bytes,
    requestSig: requestSig,
  };
};

export const verifyRequestSignature = (coin_request) => {
  const {
    pk_coin_bytes, proof_bytes, pk_client_bytes, requestSig,
  } = coin_request; // object destructuring
  const [bytesW, bytesCm, bytesR] = proof_bytes;
  const reducer = (acc, cur) => acc + cur;

  const requestStr =
    pk_client_bytes.reduce(reducer) + // client's key
    // value.toString() + // coin's value
    pk_coin_bytes.reduce(reducer) + // coin's pk
    bytesW.reduce(reducer) + // part of proof of coin's secret
    bytesCm.reduce(reducer) + // part of proof of coin's secret
    bytesR.reduce(reducer); // part of proof of coin's secret

  const sha = ctx.ECDH.HASH_TYPE;
  const [C, D] = requestSig;

  return ctx.ECDH.ECPVP_DSA(sha, pk_client_bytes, requestStr, C, D) === 0;
};

export const verifyRequestProofOfCoinSecret = (proof_bytes, pk_coin_bytes, issuer) => {
  const proof = fromBytesProof(proof_bytes);
  const pk_coin = ctx.ECP2.fromBytes(pk_coin_bytes);
  return verifyProofOfSecret(params, pk_coin, proof, issuer);
};
