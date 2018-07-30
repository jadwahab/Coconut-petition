import { ctx, params } from '../config';

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

export const getSimplifiedSignature = (signature) => {
  const [h, sig] = signature;
  const sigBytes = [];
  const hBytes = [];
  sig.toBytes(sigBytes);
  h.toBytes(hBytes);

  return [hBytes, sigBytes];
};

export const getRandomNumber = () => {
  const [G, o, g1, g2, e] = params;
  return ctx.BIG.randomnum(o, G.rngGen);
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
