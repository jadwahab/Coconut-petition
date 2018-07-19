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
