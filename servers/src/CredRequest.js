import { ctx, params } from './globalConfig';
import { prepareProofOfSecret, verifyProofOfSecret, fromBytesProof } from './auxiliary';

export const getBytesProof = (proof) => {
  const [W, cm, r] = proof;
  const bytesW = [];
  const bytesCm = [];
  const bytesR = [];
  W.toBytes(bytesW);
  cm.toBytes(bytesCm);
  r.toBytes(bytesR);

  return [bytesW, bytesCm, bytesR];
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

export const getBytesMPVP = (proof) => {
  const [enc_v, C, Cv, rk, rv, rr1, rr2] = proof;
  const [a, b] = enc_v;
  const bytesA = [];
  const bytesB = [];
  const bytesC = [];
  const bytesCv = [];
  const bytesRk = [];
  const bytesRv = [];
  const bytesRr1 = [];
  const bytesRr2 = [];
  a.toBytes(bytesA);
  b.toBytes(bytesB);
  C.toBytes(bytesC);
  Cv.toBytes(bytesCv);
  rk.toBytes(bytesRk);
  rv.toBytes(bytesRv);
  rr1.toBytes(bytesRr1);
  rr2.toBytes(bytesRr2);

  return [bytesA, bytesB, bytesC, bytesCv, bytesRk, bytesRv, bytesRr1, bytesRr2];
};

export const getCredRequestObject = (
  sk_cred, // to generate proof of secret
  pk_cred, // part of the cred
  // value, // part of the cred
  pk_client_bytes, // part of the cred
  sk_client, // to sign the request
  issuingServer, // to include in the proof of secret, it just has to be some string
) => {
  const [G, o, g1, g2, e] = params;

  const pk_cred_bytes = [];
  pk_cred.toBytes(pk_cred_bytes);
  const secretProof = prepareProofOfSecret(params, sk_cred, issuingServer);
  const proof_bytes = getBytesProof(secretProof);

  const [bytesW, bytesCm, bytesR] = proof_bytes; // expand to include in our signature

  // we just need to have same representation of both the string on both ends
  // so for bytes representations, just add up the bytes (it is quicker than concating all elements)
  const reducer = (acc, cur) => acc + cur;

  const requestStr =
    pk_client_bytes.reduce(reducer) + // client's key
    // value.toString() + // cred's value
    pk_cred_bytes.reduce(reducer) + // cred's pk
    bytesW.reduce(reducer) + // part of proof of cred's secret
    bytesCm.reduce(reducer) + // part of proof of cred's secret
    bytesR.reduce(reducer); // part of proof of cred's secret

  const sha = ctx.ECDH.HASH_TYPE;

  const C = [];
  const D = [];

  // to 'authorise' the request
  ctx.ECDH.ECPSP_DSA(sha, G.rngGen, sk_client, requestStr, C, D);
  const requestSig = [C, D];
  return {
    pk_cred_bytes: pk_cred_bytes,
    proof_bytes: proof_bytes,
    // value: value,
    pk_client_bytes: pk_client_bytes,
    requestSig: requestSig,
  };
};

export const verifyRequestSignature = (cred_request) => {
  const {
    pk_cred_bytes, proof_bytes, pk_client_bytes, requestSig,
  } = cred_request; // object destructuring
  const [bytesW, bytesCm, bytesR] = proof_bytes;
  const reducer = (acc, cur) => acc + cur;

  const requestStr =
    pk_client_bytes.reduce(reducer) + // client's key
    // value.toString() + // cred's value
    pk_cred_bytes.reduce(reducer) + // cred's pk
    bytesW.reduce(reducer) + // part of proof of cred's secret
    bytesCm.reduce(reducer) + // part of proof of cred's secret
    bytesR.reduce(reducer); // part of proof of cred's secret

  const sha = ctx.ECDH.HASH_TYPE;
  const [C, D] = requestSig;

  return ctx.ECDH.ECPVP_DSA(sha, pk_client_bytes, requestStr, C, D) === 0;
};

export const verifyRequestProofOfCredSecret = (proof_bytes, pk_cred_bytes, issuer) => {
  const proof = fromBytesProof(proof_bytes);
  const pk_cred = ctx.ECP.fromBytes(pk_cred_bytes);
  pk_cred.affine();
  return verifyProofOfSecret(params, pk_cred, proof, issuer);
};
