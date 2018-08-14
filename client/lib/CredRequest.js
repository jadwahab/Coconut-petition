import { ctx, params } from '../src/config';
import { getBytesProof, fromBytesProof } from './BytesConversion';
import { prepareProofOfSecret, verifyProofOfSecret } from './Proofs';

export const getCredRequestObject = (
  sk_cred, // to generate proof of secret
  pk_cred, // part of the cred
  pk_client_bytes, // part of the cred
  sk_client, // to sign the request
  issuingServerStr, // to include in the proof of secret, it just has to be some string
) => {
  const [G, o, g1, g2, e] = params;

  const pk_cred_bytes = [];
  pk_cred.toBytes(pk_cred_bytes);
  const secretProof = prepareProofOfSecret(params, sk_cred, issuingServerStr);
  const proof_bytes = getBytesProof(secretProof);

  const [bytesC, bytesRm, bytesRo] = proof_bytes; // expand to include in our signature

  // we just need to have same representation of both the string on both ends
  // so for bytes representations, just add up the bytes (it is quicker than concating all elements)
  const reducer = (acc, cur) => acc + cur;

  const requestStr =
    pk_client_bytes.reduce(reducer) + // client's key
    pk_cred_bytes.reduce(reducer) + // cred's pk
    bytesC.reduce(reducer) + // part of proof of cred's secret
    bytesRm.reduce(reducer) + // part of proof of cred's secret
    bytesRo.reduce(reducer); // part of proof of cred's secret

  const sha = ctx.ECDH.HASH_TYPE;

  const C = [];
  const D = [];

  // to 'authorise' the request
  ctx.ECDH.ECPSP_DSA(sha, G.rngGen, sk_client, requestStr, C, D);
  const requestSig = [C, D];
  return {
    pk_cred_bytes: pk_cred_bytes,
    proof_bytes: proof_bytes,
    pk_client_bytes: pk_client_bytes,
    requestSig: requestSig,
  };
};

export const verifyRequestSignature = (cred_request) => {
  const {
    pk_cred_bytes, proof_bytes, // pk_client_bytes, requestSig,
    pk_client_bytes, requestSig,
  } = cred_request; // object destructuring
  const [bytesW, bytesCm, bytesR] = proof_bytes;
  const reducer = (acc, cur) => acc + cur;

  const requestStr =
    pk_client_bytes.reduce(reducer) + // client's key
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
  return verifyProofOfSecret(params, pk_cred, proof, issuer);
};
