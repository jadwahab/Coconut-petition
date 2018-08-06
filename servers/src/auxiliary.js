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

export const prepareProofOfSecret = (params, sk, verifierStr) => {
  const [G, o, g1, g2, e, h1] = params;
  const m = sk.m;
  const o_blind = sk.o;
  // create random witnesses
  const wm = ctx.BIG.randomnum(G.order, G.rngGen);
  const wo = ctx.BIG.randomnum(G.order, G.rngGen);

  const W = ctx.PAIR.G1mul(g1, wm);
  const blind_factor = ctx.PAIR.G1mul(h1, wo);
  W.add(blind_factor);
  W.affine();

  const C = hashToBIG(W.toString() + verifierStr);

  // to prevent object mutation
  const m_cpy = new ctx.BIG(m);
  const C_cpy = new ctx.BIG(C);
  const o_cpy = new ctx.BIG(o_blind);
  m_cpy.mod(o);
  C_cpy.mod(o);
  o_cpy.mod(o);

  const t1 = ctx.BIG.mul(m_cpy, C_cpy); // produces DBIG
  const t2 = t1.mod(o); // but this gives BIG back
  const rm = new ctx.BIG(wm);
  rm.sub(t2);
  rm.add(o); // to ensure positive result
  rm.mod(o);

  const t3 = ctx.BIG.mul(o_cpy, C_cpy); // produces DBIG
  const t4 = t3.mod(o); // but this gives BIG back
  const ro = new ctx.BIG(wo);
  ro.sub(t4);
  ro.add(o); // to ensure positive result
  ro.mod(o);

  return [C, rm, ro];
};

export const verifyProofOfSecret = (params, pub, proof, verifierStr) => {
  const [G, o, g1, g2, e, h1] = params;
  const [C, rm, ro] = proof;

  const W_prove = ctx.PAIR.G1mul(g1, rm);
  const t1 = ctx.PAIR.G1mul(h1, ro);
  const t2 = ctx.PAIR.G1mul(pub, C);

  W_prove.add(t1);
  W_prove.add(t2);
  W_prove.affine();

  const expr = ctx.BIG.comp(C, hashToBIG(W_prove.toString() + verifierStr)) === 0;

  return expr;
};

export const prepareProofOfSecret_Auth = (params, h, sks, d, k) => {
  const [G, o, g1, g2, e, h1] = params;
  const m = sks.m;
  const o_blind = sks.o;

  // create random witnesses
  const wd = ctx.BIG.randomnum(G.order, G.rngGen);
  const wm = ctx.BIG.randomnum(G.order, G.rngGen);
  const wo = ctx.BIG.randomnum(G.order, G.rngGen);
  const wk = ctx.BIG.randomnum(G.order, G.rngGen);

  const Aw = ctx.PAIR.G1mul(g1, wd);
  Aw.affine();
  
  const Bw = ctx.PAIR.G1mul(g1, wm);
  const blind_factor = ctx.PAIR.G1mul(h1, wo);
  Bw.add(blind_factor);
  Bw.affine();

  const Cw_0 = ctx.PAIR.G1mul(g1, wk);
  Cw_0.affine();
  const elgamal_pk = ctx.PAIR.G1mul(g1, d);
  const Cw_1 = ctx.PAIR.G1mul(elgamal_pk, wk);
  const temp = ctx.PAIR.G1mul(h, wm);
  Cw_1.add(temp);
  Cw_1.affine();
  const Cw = [Cw_0, Cw_1];

  const C = hashToBIG(g1.toString() + g2.toString() + h.toString() + elgamal_pk.toString() +
  Aw.toString() + Bw.toString() + Cw.toString());

  // to prevent object mutation
  const d_cpy = new ctx.BIG(d);
  const m_cpy = new ctx.BIG(m);
  const o_cpy = new ctx.BIG(o_blind);
  const k_cpy = new ctx.BIG(k);
  const C_cpy = new ctx.BIG(C);
  d_cpy.mod(o);
  m_cpy.mod(o);
  o_cpy.mod(o);
  k_cpy.mod(o);
  C_cpy.mod(o);

  // rd
  const td1 = ctx.BIG.mul(d_cpy, C_cpy); // produces DBIG
  const td2 = td1.mod(o); // but this gives BIG back
  const rd = new ctx.BIG(wd);
  rd.sub(td2);
  rd.add(o); // to ensure positive result
  rd.mod(o);

  // rm
  const tm1 = ctx.BIG.mul(m_cpy, C_cpy); // produces DBIG
  const tm2 = tm1.mod(o); // but this gives BIG back
  const rm = new ctx.BIG(wm);
  rm.sub(tm2);
  rm.add(o); // to ensure positive result
  rm.mod(o);

  // ro
  const to1 = ctx.BIG.mul(o_cpy, C_cpy); // produces DBIG
  const to2 = to1.mod(o); // but this gives BIG back
  const ro = new ctx.BIG(wo);
  ro.sub(to2);
  ro.add(o); // to ensure positive result
  ro.mod(o);

  // rk
  const tk1 = ctx.BIG.mul(k_cpy, C_cpy); // produces DBIG
  const tk2 = tk1.mod(o); // but this gives BIG back
  const rk = new ctx.BIG(wk);
  rk.sub(tk2);
  rk.add(o); // to ensure positive result
  rk.mod(o);

  return [C, rd, rm, ro, rk];
};

export const verifyProofOfSecret_Auth = (params, h, coin_pk, elgamal_pk, enc_sk, proof) => {
  const [G, o, g1, g2, e, h1] = params;
  const [C, rd, rm, ro, rk] = proof;

  const Aw_prove = ctx.PAIR.G1mul(g1, rd);
  const tAw1 = ctx.PAIR.G1mul(elgamal_pk, C);
  Aw_prove.add(tAw1);
  Aw_prove.affine();

  const Bw_prove = ctx.PAIR.G1mul(g1, rm);
  const tBw1 = ctx.PAIR.G1mul(h1, ro);
  const tBw2 = ctx.PAIR.G1mul(coin_pk, C);
  Bw_prove.add(tBw1);
  Bw_prove.add(tBw2);
  Bw_prove.affine();

  const Cw_0_prove = ctx.PAIR.G1mul(g1, rk);
  const tCw_0 = ctx.PAIR.G1mul(enc_sk[0], C);
  Cw_0_prove.add(tCw_0);
  Cw_0_prove.affine();

  const Cw_1_prove = ctx.PAIR.G1mul(elgamal_pk, rk);
  const tCw_1 = ctx.PAIR.G1mul(h, rm);
  const t2Cw_1 = ctx.PAIR.G1mul(enc_sk[1], C);
  Cw_1_prove.add(tCw_1);
  Cw_1_prove.add(t2Cw_1);

  const Cw_prove = [Cw_0_prove, Cw_1_prove];

  const C_prove = hashToBIG(g1.toString() + g2.toString() + h.toString() + elgamal_pk.toString() +
  Aw_prove.toString() + Bw_prove.toString() + Cw_prove.toString());

  const expr = ctx.BIG.comp(C, C_prove) === 0;

  return expr;
};

export const fromBytesProof = (bytesProof) => {
  const [bytesC, bytesRm, bytesRo] = bytesProof;
  const C = ctx.BIG.fromBytes(bytesC);
  const rm = ctx.BIG.fromBytes(bytesRm);
  const ro = ctx.BIG.fromBytes(bytesRo);
  return [C, rm, ro];
};

export const fromBytesProof_Auth = (bytesProof) => {
  const [bytesC, bytesRd, bytesRm, bytesRo, bytesRk] = bytesProof;
  const C = ctx.BIG.fromBytes(bytesC);
  const rd = ctx.BIG.fromBytes(bytesRd);
  const rm = ctx.BIG.fromBytes(bytesRm);
  const ro = ctx.BIG.fromBytes(bytesRo);
  const rk = ctx.BIG.fromBytes(bytesRk);
  return [C, rd, rm, ro, rk];
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

export const fromBytesMPVP = (bytesProof) => {
  const [bytesA, bytesB, bytesC, bytesCv, bytesRk, bytesRv, bytesRr1, bytesRr2] = bytesProof;
  const a = ctx.ECP.fromBytes(bytesA);
  const b = ctx.ECP.fromBytes(bytesB);
  const enc_v = [a, b];
  const C = ctx.BIG.fromBytes(bytesC);
  const Cv = ctx.ECP.fromBytes(bytesCv);
  const rk = ctx.BIG.fromBytes(bytesRk);
  const rv = ctx.BIG.fromBytes(bytesRv);
  const rr1 = ctx.BIG.fromBytes(bytesRr1);
  const rr2 = ctx.BIG.fromBytes(bytesRr2);
  return [enc_v, C, Cv, rk, rv, rr1, rr2];
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
