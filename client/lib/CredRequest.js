import { ctx, params } from '../src/config';
import { prepareProofOfSecret, verifyProofOfSecret } from './auxiliary';

export const getBytesProof = (proof) => {
  const [C, rm, ro] = proof;
  const bytesC = [];
  const bytesRm = [];
  const bytesRo = [];
  C.toBytes(bytesC);
  rm.toBytes(bytesRm);
  ro.toBytes(bytesRo);

  return [bytesC, bytesRm, bytesRo];
};

export const getBytesProof_Auth = (proof) => {
  const [C, rd, rm, ro, rk] = proof;
  const bytesC = [];
  const bytesRd = [];
  const bytesRm = [];
  const bytesRo = [];
  const bytesRk = [];
  C.toBytes(bytesC);
  rd.toBytes(bytesRd);
  rm.toBytes(bytesRm);
  ro.toBytes(bytesRo);
  rk.toBytes(bytesRk);

  return [bytesC, bytesRd, bytesRm, bytesRo, bytesRk];
};

export const getCredRequestObject = (
  sk_coin, // to generate proof of secret
  pk_coin, // part of the coin
  pk_client_bytes, // part of the coin
  sk_client, // to sign the request
  issuingServerStr, // to include in the proof of secret, it just has to be some string
) => {
  const [G, o, g1, g2, e] = params;

  const pk_coin_bytes = [];
  pk_coin.toBytes(pk_coin_bytes);
  const secretProof = prepareProofOfSecret(params, sk_coin, issuingServerStr);
  const proof_bytes = getBytesProof(secretProof);

  const [bytesC, bytesRm, bytesRo] = proof_bytes; // expand to include in our signature

  // we just need to have same representation of both the string on both ends
  // so for bytes representations, just add up the bytes (it is quicker than concating all elements)
  const reducer = (acc, cur) => acc + cur;

  const requestStr =
    pk_client_bytes.reduce(reducer) + // client's key
    pk_coin_bytes.reduce(reducer) + // coin's pk
    bytesC.reduce(reducer) + // part of proof of coin's secret
    bytesRm.reduce(reducer) + // part of proof of coin's secret
    bytesRo.reduce(reducer); // part of proof of coin's secret

  const sha = ctx.ECDH.HASH_TYPE;

  const C = [];
  const D = [];

  // to 'authorise' the request
  ctx.ECDH.ECPSP_DSA(sha, G.rngGen, sk_client, requestStr, C, D);
  const requestSig = [C, D];
  return {
    pk_coin_bytes: pk_coin_bytes,
    proof_bytes: proof_bytes,
    pk_client_bytes: pk_client_bytes,
    requestSig: requestSig,
  };
};

export const verifyRequestSignature = (coin_request) => {
  const {
    pk_coin_bytes, proof_bytes, // pk_client_bytes, requestSig,
      pk_client_bytes, requestSig,
  } = coin_request; // object destructuring
  const [bytesW, bytesCm, bytesR] = proof_bytes;
  const reducer = (acc, cur) => acc + cur;

  const requestStr =
    pk_client_bytes.reduce(reducer) + // client's key
    pk_coin_bytes.reduce(reducer) + // coin's pk
    bytesW.reduce(reducer) + // part of proof of coin's secret
    bytesCm.reduce(reducer) + // part of proof of coin's secret
    bytesR.reduce(reducer); // part of proof of coin's secret

  const sha = ctx.ECDH.HASH_TYPE;
  const [C, D] = requestSig;

  return ctx.ECDH.ECPVP_DSA(sha, pk_client_bytes, requestStr, C, D) === 0;
};

export const fromBytesProof = (bytesProof) => {
  const [bytesW, bytesCm, bytesR] = bytesProof;
  const W = ctx.ECP.fromBytes(bytesW);
  const cm = ctx.BIG.fromBytes(bytesCm);
  const r = ctx.BIG.fromBytes(bytesR);
  return [W, cm, r];
};

export const verifyRequestProofOfCredSecret = (proof_bytes, pk_coin_bytes, issuer) => {
  const proof = fromBytesProof(proof_bytes);
  const pk_coin = ctx.ECP.fromBytes(pk_coin_bytes);
  return verifyProofOfSecret(params, pk_coin, proof, issuer);
};