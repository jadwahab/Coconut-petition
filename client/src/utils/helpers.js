import { ctx, params } from '../config';

export const getRandomNumber = () => {
  const [G, o, g1, g2, e] = params;
  return ctx.BIG.randomnum(o, G.rngGen);
};