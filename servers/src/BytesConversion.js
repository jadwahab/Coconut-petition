import { ctx } from './globalConfig';

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

export const fromBytesProof = (bytesProof) => {
  const [bytesC, bytesRm, bytesRo] = bytesProof;
  const C = ctx.BIG.fromBytes(bytesC);
  const rm = ctx.BIG.fromBytes(bytesRm);
  const ro = ctx.BIG.fromBytes(bytesRo);
  return [C, rm, ro];
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

export const fromBytesProof_Auth = (bytesProof) => {
  const [bytesC, bytesRd, bytesRm, bytesRo, bytesRk] = bytesProof;
  const C = ctx.BIG.fromBytes(bytesC);
  const rd = ctx.BIG.fromBytes(bytesRd);
  const rm = ctx.BIG.fromBytes(bytesRm);
  const ro = ctx.BIG.fromBytes(bytesRo);
  const rk = ctx.BIG.fromBytes(bytesRk);
  return [C, rd, rm, ro, rk];
};

export const getSimplifiedProof = (proof) => {
  const [W, cm, r] = proof;
  const bytesW = [];
  const bytesCm = [];
  const bytesR = [];
  W.toBytes(bytesW);
  cm.toBytes(bytesCm);
  r.toBytes(bytesR);

  return [bytesW, bytesCm, bytesR];
};

export const fromBytesSimplifiedProof = (bytesProof) => {
  const [bytesW, bytesCm, bytesR] = bytesProof;
  const W = ctx.ECP.fromBytes(bytesW);
  const cm = ctx.BIG.fromBytes(bytesCm);
  const r = ctx.BIG.fromBytes(bytesR);
  return [W, cm, r];
};

export const getSimplifiedMPCP = (MPCP_output) => {
  const [kappa, nu, zeta, pi_v] = MPCP_output;
  const bytesKappa = [];
  const bytesNu = [];
  const bytesZeta = [];
  const bytesPi_v_c = [];
  const bytesPi_v_rm = [];
  const bytesPi_v_rt = [];
  kappa.toBytes(bytesKappa);
  nu.toBytes(bytesNu);
  zeta.toBytes(bytesZeta);
  pi_v.c.toBytes(bytesPi_v_c);
  pi_v.rm.toBytes(bytesPi_v_rm);
  pi_v.rt.toBytes(bytesPi_v_rt);

  return [bytesKappa, bytesNu, bytesZeta, bytesPi_v_c, bytesPi_v_rm, bytesPi_v_rt];
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
    rt: rt,
  };
  return [kappa, nu, zeta, pi_v];
};

export const getBytesMPVP = (proof) => {
  const [C, Cv, rk, rv, rr1, rr2] = proof;
  const bytesC = [];
  const bytesCv = [];
  const bytesRk = [];
  const bytesRv = [];
  const bytesRr1 = [];
  const bytesRr2 = [];
  C.toBytes(bytesC);
  Cv.toBytes(bytesCv);
  rk.toBytes(bytesRk);
  rv.toBytes(bytesRv);
  rr1.toBytes(bytesRr1);
  rr2.toBytes(bytesRr2);

  return [bytesC, bytesCv, bytesRk, bytesRv, bytesRr1, bytesRr2];
};

export const fromBytesMPVP = (bytesProof) => {
  const [bytesC, bytesCv, bytesRk, bytesRv, bytesRr1, bytesRr2] = bytesProof;
  const C = ctx.BIG.fromBytes(bytesC);
  const Cv = ctx.ECP.fromBytes(bytesCv);
  const rk = ctx.BIG.fromBytes(bytesRk);
  const rv = ctx.BIG.fromBytes(bytesRv);
  const rr1 = ctx.BIG.fromBytes(bytesRr1);
  const rr2 = ctx.BIG.fromBytes(bytesRr2);

  return [C, Cv, rk, rv, rr1, rr2];
};

export const getBytesVotes = (votes) => {
  const [enc_v, enc_v_not] = votes;
  const [a, b] = enc_v;
  const bytesA = [];
  const bytesB = [];
  const [a_not, b_not] = enc_v_not;
  const bytesANot = [];
  const bytesBNot = [];
  a.toBytes(bytesA);
  b.toBytes(bytesB);
  a_not.toBytes(bytesANot);
  b_not.toBytes(bytesBNot);

  return [bytesA, bytesB, bytesANot, bytesBNot];
};

export const fromBytesVotes = (bytesVotes) => {
  const [bytesA, bytesB, bytesANot, bytesBNot] = bytesVotes;
  const a = ctx.ECP.fromBytes(bytesA);
  const b = ctx.ECP.fromBytes(bytesB);
  const enc_v = [a, b];
  const a_not = ctx.ECP.fromBytes(bytesANot);
  const b_not = ctx.ECP.fromBytes(bytesBNot);
  const enc_v_not = [a_not, b_not];

  return [enc_v, enc_v_not];
};

export const getSimplifiedSignature = (signature) => {
  const [h, sig] = signature;
  const sigBytes = [];
  const hBytes = [];
  sig.toBytes(sigBytes);
  h.toBytes(hBytes);

  return [hBytes, sigBytes];
};
