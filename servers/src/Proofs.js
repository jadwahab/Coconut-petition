import { ctx } from './globalConfig';
import ElGamal from './ElGamal';

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

export const prepareProofOfSecret = (params, sk, verifierStr) => {
  const [G, o, g1, g2, e, h1] = params;
  const x = sk.m;
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
  const x_cpy = new ctx.BIG(x);
  const C_cpy = new ctx.BIG(C);
  const o_cpy = new ctx.BIG(o_blind);
  x_cpy.mod(o);
  C_cpy.mod(o);
  o_cpy.mod(o);

  const t1 = ctx.BIG.mul(x_cpy, C_cpy); // produces DBIG
  const t2 = t1.mod(o); // but this gives BIG back
  wm.mod(o);
  const rm = new ctx.BIG(wm);

  rm.copy(wm);
  rm.sub(t2);
  rm.add(o); // to ensure positive result
  rm.mod(o);

  const t3 = ctx.BIG.mul(o_cpy, C_cpy); // produces DBIG
  const t4 = t3.mod(o); // but this gives BIG back
  wo.mod(o);
  const ro = new ctx.BIG(wo);

  ro.copy(wo);
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

export const verifyProofOfSecret_Auth = (params, h, cred_pk, elgamal_pk, enc_sk, proof) => {
  const [G, o, g1, g2, e, h1] = params;
  const [C, rd, rm, ro, rk] = proof;

  const Aw_prove = ctx.PAIR.G1mul(g1, rd);
  const tAw1 = ctx.PAIR.G1mul(elgamal_pk, C);
  Aw_prove.add(tAw1);
  Aw_prove.affine();

  const Bw_prove = ctx.PAIR.G1mul(g1, rm);
  const tBw1 = ctx.PAIR.G1mul(h1, ro);
  const tBw2 = ctx.PAIR.G1mul(cred_pk, C);
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

export const make_proof_credentials_petition = (params, agg_vk, sigma, m, petitionOwner, petitionID) => {
  const [G, o, g1, g2, e] = params;
  // const agg_vk = CredSig.aggregatePublicKeys_obj(params, signingAuthPubKeys); // agg_vk = [ag, aX, aY]

  // MATERIALS: rand t, kappa, nu, zeta
  const t = ctx.BIG.randomnum(G.order, G.rngGen);

  // kappa = t*g2 + aX + m*aY :
  const kappa = ctx.PAIR.G2mul(g2, t); // t*g2
  const aX = agg_vk[1]; // aX
  const aY = agg_vk[2]; // aY
  const pkY = ctx.PAIR.G2mul(aY, m); // m*Y
  kappa.add(aX);
  kappa.add(pkY);
  kappa.affine();

  const [h, sig] = sigma;

  // nu = t*h
  const nu = ctx.PAIR.G1mul(h, t);

  const gs = hashToPointOnCurve(petitionID);

  // zeta = m*gs
  const zeta = ctx.PAIR.G1mul(gs, m);

  // PROOF: pi_v
  // create witnesses
  const wm = ctx.BIG.randomnum(G.order, G.rngGen);
  const wt = ctx.BIG.randomnum(G.order, G.rngGen);

  // compute the witnesses commitments
  const Aw = ctx.PAIR.G2mul(g2, wt);
  Aw.add(aX);
  const pkYw = ctx.PAIR.G2mul(aY, wm);
  Aw.add(pkYw);
  Aw.affine();
  const Bw = ctx.PAIR.G1mul(h, wt);
  Bw.affine();
  const Cw = ctx.PAIR.G1mul(gs, wm);
  Cw.affine();

  // create the challenge
  const c = hashToBIG(g1.toString() + g2.toString() + aX.toString() + aY.toString() +
      Aw.toString() + Bw.toString() + Cw.toString() + petitionOwner.toString());

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
  const t2 = t1.mod(o); // but this gives BIG back

  const t3 = ctx.BIG.mul(t_cpy, c_cpy); // produces DBIG
  const t4 = t3.mod(o); // but this gives BIG back

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
    rt: rt,
  };

  return [kappa, nu, zeta, pi_v];
};

export const verify_proof_credentials_petition = (params, agg_vk, sigma, MPCP_output, petitionOwner, petitionID) => {
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

  // re-compute the witness commitments
  const Aw = ctx.PAIR.G2mul(kappa, c);
  const temp1 = ctx.PAIR.G2mul(g2, rt);
  Aw.add(temp1);
  Aw.add(aX);
  const temp2 = ctx.PAIR.G2mul(aX, c);
  Aw.sub(temp2);
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

  // BIG.comp(a,b): Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b
  const expr1 = ctx.BIG.comp(c, hashToBIG(g1.toString() + g2.toString() + aX.toString() + aY.toString() +
    Aw.toString() + Bw.toString() + Cw.toString() + petitionOwner.toString())) === 0;

  return (!h.INF && expr1);
};

export const make_proof_vote_petition = (params, pub, vote) => {
  const [G, o, g1, g2, e, h1] = params;
  if (typeof vote === 'number') {
    vote = new ctx.BIG(vote);
  }
  // encrypt the vote
  const [a, b, k] = ElGamal.encrypt(params, pub, vote, h1);
  const enc_v = [a, b];
  // get the inverse of the vote
  const minus1 = new ctx.BIG(-1);
  const enc_v_a = G.ctx.PAIR.G1mul(a, minus1);
  const enc_v_b = G.ctx.PAIR.G1mul(b, minus1);
  enc_v_b.add(h1);
  enc_v_b.affine();
  const enc_v_not = [enc_v_a, enc_v_b];

  const enc_votes = [enc_v, enc_v_not];

  const r1 = ctx.BIG.randomnum(G.order, G.rngGen);
  const r2 = new ctx.BIG(r1);
  const vote_cpy = new ctx.BIG(vote); // to prevent object mutation
  const t1 = ctx.BIG.mul(vote_cpy, r1); // produces DBIG
  const t2 = t1.mod(o); // but this gives BIG back
  r2.sub(t2);
  r2.add(o); // to ensure positive result
  r2.mod(o);

  const Cv = ctx.PAIR.G1mul(g1, vote);
  const temp4 = ctx.PAIR.G1mul(h1, r1);
  Cv.add(temp4);
  Cv.affine();

  // create random witnesses
  const wk = ctx.BIG.randomnum(G.order, G.rngGen);
  const wv = ctx.BIG.randomnum(G.order, G.rngGen);
  const wr1 = ctx.BIG.randomnum(G.order, G.rngGen);
  const wr2 = ctx.BIG.randomnum(G.order, G.rngGen);

  const Wa = ctx.PAIR.G1mul(g1, wk);
  Wa.affine();
  
  const Wb = ctx.PAIR.G1mul(pub, wk);
  const blind_factor = ctx.PAIR.G1mul(h1, wv);
  Wb.add(blind_factor);
  Wb.affine();

  const WCv = ctx.PAIR.G1mul(g1, wv);
  const blind_factor2 = ctx.PAIR.G1mul(h1, wr1);
  WCv.add(blind_factor2);
  WCv.affine();
  
  const WCv2 = ctx.PAIR.G1mul(Cv, wv);
  const blind_factor3 = ctx.PAIR.G1mul(h1, wr2);
  WCv2.add(blind_factor3);
  WCv2.affine();

  const C = hashToBIG(g1.toString() + h1.toString() + a.toString() + b.toString() +
    Cv.toString() + Wa.toString() + Wb.toString() + WCv.toString() + WCv2.toString());

  // to prevent object mutation
  const k_cpy = new ctx.BIG(k);
  const v_cpy = new ctx.BIG(vote);
  const r1_cpy = new ctx.BIG(r1);
  const r2_cpy = new ctx.BIG(r2);
  const C_cpy = new ctx.BIG(C);
  k_cpy.mod(o);
  v_cpy.mod(o);
  r1_cpy.mod(o);
  r2_cpy.mod(o);
  C_cpy.mod(o);

  // rk
  const tk1 = ctx.BIG.mul(k_cpy, C_cpy); // produces DBIG
  const tk2 = tk1.mod(o); // but this gives BIG back
  const rk = new ctx.BIG(wk);
  rk.sub(tk2);
  rk.add(o); // to ensure positive result
  rk.mod(o);
  
  // rv
  const tv1 = ctx.BIG.mul(v_cpy, C_cpy); // produces DBIG
  const tv2 = tv1.mod(o); // but this gives BIG back
  const rv = new ctx.BIG(wv);
  rv.sub(tv2);
  rv.add(o); // to ensure positive result
  rv.mod(o);

  // rr1
  const tr1_1 = ctx.BIG.mul(r1_cpy, C_cpy); // produces DBIG
  const tr1_2 = tr1_1.mod(o); // but this gives BIG back
  const rr1 = new ctx.BIG(wr1);
  rr1.sub(tr1_2);
  rr1.add(o); // to ensure positive result
  rr1.mod(o);

  // rr2
  const tr2_1 = ctx.BIG.mul(r2_cpy, C_cpy); // produces DBIG
  const tr2_2 = tr2_1.mod(o); // but this gives BIG back
  const rr2 = new ctx.BIG(wr2);
  rr2.sub(tr2_2);
  rr2.add(o); // to ensure positive result
  rr2.mod(o);

  const MPVP_output = [C, Cv, rk, rv, rr1, rr2];

  return [enc_votes, MPVP_output];
};

export const verify_proof_vote_petition = (params, pub, MPVP_output, enc_v) => {
  const [G, o, g1, g2, e, h1] = params;
  const [C, Cv, rk, rv, rr1, rr2] = MPVP_output;
  const [a, b] = enc_v;

  const Wa_prove = ctx.PAIR.G1mul(g1, rk);
  const tWa1 = ctx.PAIR.G1mul(a, C);
  Wa_prove.add(tWa1);
  Wa_prove.affine();

  const Wb_prove = ctx.PAIR.G1mul(pub, rk);
  const tWb1 = ctx.PAIR.G1mul(h1, rv);
  const tWb2 = ctx.PAIR.G1mul(b, C);
  Wb_prove.add(tWb1);
  Wb_prove.add(tWb2);
  Wb_prove.affine();

  const WCv_prove = ctx.PAIR.G1mul(g1, rv);
  const tWCv1 = ctx.PAIR.G1mul(h1, rr1);
  const tWCv2 = ctx.PAIR.G1mul(Cv, C);
  WCv_prove.add(tWCv1);
  WCv_prove.add(tWCv2);
  WCv_prove.affine();
  
  const WCv2_prove = ctx.PAIR.G1mul(Cv, rv);
  const tWCv2_1 = ctx.PAIR.G1mul(h1, rr2);
  const tWCv2_2 = ctx.PAIR.G1mul(Cv, C);
  WCv2_prove.add(tWCv2_1);
  WCv2_prove.add(tWCv2_2);
  WCv2_prove.affine();

  const C_prove = hashToBIG(g1.toString() + h1.toString() + a.toString() + b.toString() +
  Cv.toString() + Wa_prove.toString() + Wb_prove.toString() + WCv_prove.toString() + WCv2_prove.toString());

  const expr = ctx.BIG.comp(C, C_prove) === 0;

  return expr;
};
