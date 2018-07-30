// set of auxiliary functions that don't belong to any existing class/module
import fetch from 'isomorphic-fetch';
import * as crypto from 'crypto';
import { ctx } from './globalConfig';

export const stringToBytes = (s) => {
  const b = [];
  for (let i = 0; i < s.length; i++) {
    b.push(s.charCodeAt(i));
  }
  return b;
};

export const hashMessage = (m) => {
  const messageBytes = stringToBytes(m);
  const H = new ctx.HASH256();
  H.process_array(messageBytes);
  return H.hash();
};

export const hashToBIG = (m) => {
  const R = hashMessage(m);
  return ctx.BIG.fromBytes(R);
};

// implementation partially taken from https://github.com/milagro-crypto/milagro-crypto-js/blob/develop/src/mpin.js#L151
// From MPIN API - hashit: function(sha, n, B)
export const hashToPointOnCurve = (m) => {
  const R = hashMessage(m);

  if (R.length === 0) return null;
  const W = [];

  // needs to be adjusted if different curve was to be chosen
  const sha = 32;
  if (sha >= ctx.BIG.MODBYTES) {
    for (let i = 0; i < ctx.BIG.MODBYTES; i++) W[i] = R[i];
  } else {
    for (let i = 0; i < sha; i++) W[i] = R[i];
    for (let i = sha; i < ctx.BIG.MODBYTES; i++) W[i] = 0;
  }
  return ctx.ECP.mapit(W);
};

export const hashG2ElemToBIG = G2elem => hashToBIG(G2elem.toString());

// the below are in coinGenerator of client
export const getRandomCoinId = () => {
  const RAW = crypto.randomBytes(128);

  const rng = new ctx.RAND();
  rng.clean();
  rng.seed(RAW.length, RAW);
  const groupOrder = new ctx.BIG(0);
  groupOrder.rcopy(ctx.ROM_CURVE.CURVE_Order);

  return ctx.BIG.randomnum(groupOrder, rng);
};

export const prepareProofOfSecret = (params, x, verifierStr, proofBase = null) => {
  const [G, o, g1, g2, e] = params;
  const w = ctx.BIG.randomnum(G.order, G.rngGen);
  let W;
  if (!proofBase) {
    W = ctx.PAIR.G2mul(g2, w);
  } else {
    W = ctx.PAIR.G2mul(proofBase, w);
  }
  const cm = hashToBIG(W.toString() + verifierStr);

  // to prevent object mutation
  const x_cpy = new ctx.BIG(x);
  const cm_cpy = new ctx.BIG(cm);
  x_cpy.mod(o);
  cm_cpy.mod(o);

  const t1 = ctx.BIG.mul(x_cpy, cm_cpy); // produces DBIG
  const t2 = t1.mod(o); // but this gives BIG back

  w.mod(o);
  const r = new ctx.BIG(w);

  r.copy(w);
  r.sub(t2);
  r.add(o); // to ensure positive result
  r.mod(o);

  return [W, cm, r]; // G2Elem, BIG, BIG
};

export const verifyProofOfSecret = (params, pub, proof, verifierStr, proofBase = null) => {
  const [G, o, g1, g2, e] = params;
  const [W, cm, r] = proof;

  let t1;
  if (!proofBase) {
    t1 = ctx.PAIR.G2mul(g2, r);
  } else {
    t1 = ctx.PAIR.G2mul(proofBase, r);
  }

  const t2 = ctx.PAIR.G2mul(pub, cm);

  t1.add(t2);
  t1.affine();

  const expr1 = t1.equals(W);
  const expr2 = ctx.BIG.comp(cm, hashToBIG(W.toString() + verifierStr)) === 0;

  return expr1 && expr2;
};

export const fromBytesProof = (bytesProof) => {
  const [bytesW, bytesCm, bytesR] = bytesProof;
  const W = ctx.ECP2.fromBytes(bytesW);
  const cm = ctx.BIG.fromBytes(bytesCm);
  const r = ctx.BIG.fromBytes(bytesR);
  return [W, cm, r];
};


export const fromBytesMPCP = (bytesMPCP) => {
  const [bytesKappa, bytesNu, bytesZeta, bytesPi_v_c, bytesPi_v_rm, bytesPi_v_rt] = bytesMPCP;
  const kappa = ctx.ECP2.fromBytes(bytesKappa);
  const nu = ctx.ECP.fromBytes(bytesNu);
  const zeta = ctx.ECP.fromBytes(bytesZeta);
  const c = ctx.BIG.fromBytes(bytesPi_v_c);
  const rm = ctx.BIG.fromBytes(bytesPi_v_rm);
  const rt = ctx.BIG.fromBytes(bytesPi_v_rt);
  const pi_v = {
    c: c,
    rm: rm,
    rt: rt
  };
  return [kappa, nu, zeta, pi_v];
};

export const getPublicKey = async (server) => {
  try {
    let response = await fetch(`http://${server}/pk`);
    response = await response.json();
    return response.pk;
  } catch (err) {
    console.log(err);
    console.warn(`Call to ${server} was unsuccessful`);
    return null;
  }
};

export async function getSigningAuthorityPublicKey(server) {
  const publicKey = [];
  try {
    let response = await fetch(`http://${server}/pk`);
    response = await response.json();
    const pkBytes = response.pk;
    const [gBytes, XBytes, YBytes] = pkBytes;
    publicKey.push(ctx.ECP2.fromBytes(gBytes));
    publicKey.push(ctx.ECP2.fromBytes(XBytes));
    publicKey.push(ctx.ECP2.fromBytes(YBytes));
  } catch (err) {
    console.log(err);
    console.warn(`Call to ${server} was unsuccessful`);
  }
  return publicKey;
}

// EDIT: move to proofs.js
export const verify_proof_credentials_petition = (params, agg_vk, sigma, MPCP_output, petitionID) => {
  if (!sigma) {
    return false;
  }
  const [G, o, g1, g2, e] = params;
  const [ag, aX, aY] = agg_vk;
  const [h, sig] = sigma;
  const [kappa, nu, zeta, pi_v] = MPCP_output;
  const c = pi_v.c;
  const rm = pi_v.rm;
  const rt = pi_v.rt;
  const gs = hashToPointOnCurve(petitionID);

  // for some reason h.x, h.y, sig.x and sig.y return false to being instances of FP when signed by SAs,
  // hence temporary, ugly hack:
  // I blame javascript pseudo-broken typesystem
  const tempX1 = new G.ctx.FP(0);
  const tempY1 = new G.ctx.FP(0);
  tempX1.copy(h.getx());
  tempY1.copy(h.gety());
  h.x = tempX1;
  h.y = tempY1;

  const tempX2 = new G.ctx.FP(0);
  const tempY2 = new G.ctx.FP(0);
  tempX2.copy(sig.getx());
  tempY2.copy(sig.gety());
  sig.x = tempX2;
  sig.y = tempY2;


  // re-compute the witness commitments
  let Aw = ctx.PAIR.G2mul(kappa, c);
  const temp1 = ctx.PAIR.G2mul(g2, rt);
  Aw.add(temp1);
  const oneMinusC = new ctx.BIG(1);
  oneMinusC.sub(c);
  oneMinusC.add(o); // to ensure positive result
  oneMinusC.mod(o);
  const temp2 = ctx.PAIR.G2mul(aX, oneMinusC);
  Aw.add(temp2);
  const temp3 = ctx.PAIR.G2mul(aY, rm);
  Aw.add(temp3);
  Aw.affine();

  let Bw = ctx.PAIR.G1mul(nu, c);
  const temp4 = ctx.PAIR.G1mul(h, rt);
  Bw.add(temp4);
  Bw.affine();

  let Cw = ctx.PAIR.G1mul(gs, rm);
  const temp5 = ctx.PAIR.G1mul(zeta, c);
  Cw.add(temp5);
  Cw.affine();

  // BIG.comp(a,b): Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b
  const expr1 = ctx.BIG.comp(c, hashToBIG(g1.toString() + g2.toString() + aX.toString() + aY.toString() + Aw.toString() + Bw.toString() + Cw.toString())) === 0;

  return (!h.INF && expr1);
}
