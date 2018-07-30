// set of auxiliary functions that don't belong to any existing class/module

import { ctx } from '../src/config';
import CoinSig from './CoinSig';

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

export const hashG2ElemToBIG = (G2elem) => {
  return this.hashToBIG(G2elem.toString());
};

// EDIT: move to file called proofs.js
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


export const make_proof_credentials_petition = (params, agg_vk, sigma, m, petitionID) => {
  const [G, o, g1, g2, e] = params;
  // const agg_vk = CoinSig.aggregatePublicKeys_obj(params, signingAuthPubKeys); // agg_vk = [ag, aX, aY]

  // MATERIALS: rand t, kappa, nu, zeta
  const t = ctx.BIG.randomnum(G.order, G.rngGen);

  // kappa = t*g2 + aX + m*aY :
  const kappa = ctx.PAIR.G2mul(g2, t);   // t*g2
  const aX = agg_vk[1];                  // aX
  const aY = agg_vk[2];                  // aY
  const pkY = ctx.PAIR.G2mul(aY, m);     // m*Y
  kappa.add(aX);
  kappa.add(pkY);
  kappa.affine();

  const [h, sig] = sigma;

  // nu = t*h
  // EDIT: DEPENDS ON IF Cm USED G1 OR G2 in generateCoinSecret of CredentialRequester.js
  const nu = ctx.PAIR.G1mul(h, t);  //QUEST: WHY HAD TO CHANGE TO G1??

  const gs = hashToPointOnCurve(petitionID);

  // zeta = m*gs
  zeta = ctx.PAIR.G1mul(gs, m);     //QUEST: WHY HAD TO CHANGE TO G1??

  // PROOF: pi_v
  // create witnesses
  const wm = ctx.BIG.randomnum(G.order, G.rngGen);
  const wt = ctx.BIG.randomnum(G.order, G.rngGen);

  // compute the witnesses commitments
  const Aw = ctx.PAIR.G2mul(g2,wt);
  Aw.add(aX);
  const pkYw = ctx.PAIR.G2mul(aY, wm);
  Aw.add(pkYw);
  Aw.affine();
  const Bw = ctx.PAIR.G1mul(h, wt);
  const Cw = ctx.PAIR.G1mul(gs, wm);

  console.log('MPCP:');
  console.log('Aw');
  console.log(Aw);
  console.log('Bw');
  console.log(Bw);
  console.log('Cw');
  console.log(Cw);

  // create the challenge
  const c = hashToBIG(g1.toString() + g2.toString() + aX.toString() + aY.toString() + Aw.toString() + Bw.toString() + Cw.toString());

  // create responses
  const rm = new ctx.BIG(wm);
  const rt = new ctx.BIG(wt);

  // to prevent object mutation
  const m_cpy = new ctx.BIG(m);
  const t_cpy = new ctx.BIG(t);
  const c_cpy = new ctx.BIG(c);
  m_cpy.mod(o);
  t_cpy.mod(o);
  c_cpy.mod(o);

  const t1 = ctx.BIG.mul(m_cpy, c_cpy); // produces DBIG
  const t2 = t1.mod(o); // but this gives BIG back          EDIT: check if can remove t2 and t4 useless

  const t3 = ctx.BIG.mul(t_cpy, c_cpy); // produces DBIG
  const t4 = t1.mod(o); // but this gives BIG back

  wm.mod(o);
  wt.mod(o);

  rm.sub(t2);
  rm.add(o); // to ensure positive result
  rm.mod(o);

  rt.sub(t4);
  rt.add(o); // to ensure positive result
  rt.mod(o);

  const pi_v = {
    c: c,
    rm: rm,
    rt: rt
  };

  return [kappa, nu, zeta, pi_v];
};


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


  // // for some reason h.x, h.y, sig.x and sig.y return false to being instances of FP when signed by SAs,
  // // hence temporary, ugly hack:
  // // I blame javascript pseudo-broken typesystem
  // const tempX1 = new G.ctx.FP(0);
  // const tempY1 = new G.ctx.FP(0);
  // tempX1.copy(h.getx());
  // tempY1.copy(h.gety());
  // h.x = tempX1;
  // h.y = tempY1;
  //
  // const tempX2 = new G.ctx.FP(0);
  // const tempY2 = new G.ctx.FP(0);
  // tempX2.copy(sig.getx());
  // tempY2.copy(sig.gety());
  // sig.x = tempX2;
  // sig.y = tempY2;

  // re-compute the witness commitments
  const Aw = ctx.PAIR.G2mul(kappa, c);
  const temp1 = ctx.PAIR.G2mul(g2, rt)
  Aw.add(temp1);
  const oneMinusC = new ctx.BIG(1);
  oneMinusC.sub(c);
  oneMinusC.mod(o);
  const temp2 = ctx.PAIR.G2mul(aX, oneMinusC);
  Aw.add(temp2);
  const temp3 = ctx.PAIR.G2mul(aY, rm);
  Aw.add(temp3);
  Aw.affine();

  const Bw = ctx.PAIR.G1mul(nu, c);
  const temp4 = ctx.PAIR.G1mul(h, rt);
  Bw.add(temp4);
  Bw.affine();

  const Cw = ctx.PAIR.G1mul(gs, rm);
  const temp5 = ctx.PAIR.G1mul(zeta, c);
  Cw.add(temp5);
  Cw.affine();

  console.log('VPCP:');
  console.log('Aw');
  console.log(Aw);
  console.log('Bw');
  console.log(Bw);
  console.log('Cw');
  console.log(Cw);

  // BIG.comp(a,b): Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b
  const expr1 = ctx.BIG.comp(c, hashToBIG(g1.toString() + g2.toString() + aX.toString() + aY.toString() + Aw.toString() + Bw.toString() + Cw.toString())) === 0;

  // return (!h.INF && expr1);
  return (expr1);
}
