import * as crypto from 'crypto';
import { ctx } from '../config';

// uses same RNG generator as the one used for key generation
// it is exported to be used in Cred tests
export const getRandomCredId = () => {
  const RAW = crypto.randomBytes(128);

  const rng = new ctx.RAND();
  rng.clean();
  rng.seed(RAW.length, RAW);
  const groupOrder = new ctx.BIG(0);
  groupOrder.rcopy(ctx.ROM_CURVE.CURVE_Order);

  return ctx.BIG.randomnum(groupOrder, rng);
};
