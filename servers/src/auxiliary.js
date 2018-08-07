// set of auxiliary functions that don't belong to any existing class/module
import fetch from 'isomorphic-fetch';
import * as crypto from 'crypto';
import { ctx } from './globalConfig';

// the below are in credGenerator of client
export const getRandomCredId = () => {
  const RAW = crypto.randomBytes(128);

  const rng = new ctx.RAND();
  rng.clean();
  rng.seed(RAW.length, RAW);
  const groupOrder = new ctx.BIG(0);
  groupOrder.rcopy(ctx.ROM_CURVE.CURVE_Order);

  return ctx.BIG.randomnum(groupOrder, rng);
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
