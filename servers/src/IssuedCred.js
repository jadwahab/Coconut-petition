import { ctx, params } from './globalConfig';

// const MIN_TTL_H = 12;
//
// const getHourTimeDifference = (date1, date2) => {
//   const difference = (date1.getTime() - date2.getTime()) / (1000 * 60 * 60);
//   return Math.abs(Math.round(difference));
// };
//
// const getTimeToLive = () => {
//   const currentTime = new Date();
//   const endOfDayTime = new Date(
//     currentTime.getFullYear(),
//     currentTime.getMonth(),
//     currentTime.getDate(),
//     23, 59, 59, 999,
//   );
//
//   let timeToLive;
//   const hoursUntilEndOfDay = getHourTimeDifference(currentTime, endOfDayTime);
//   // if it's less than MIN hours until end of day, set TTL to end of day plus 24h
//   if (hoursUntilEndOfDay < MIN_TTL_H) {
//     timeToLive = endOfDayTime.getTime() + 1 + (1000 * 60 * 60 * 24);
//   } else {
//     timeToLive = endOfDayTime.getTime() + 1; // otherwise just set it to end of day
//   }
//
//   return timeToLive;
// };

export const getIssuedCred = (pk_cred_bytes, pk_client_bytes, issuer_sk_Bytes) => {
  const [G, o, g1, g2, e] = params;

  // same reasoning as with CredRequest
  const reducer = (acc, cur) => acc + cur;

  const credStr =
    pk_client_bytes.reduce(reducer) + // client's key
    pk_cred_bytes.reduce(reducer); // cred's pk

  const sha = ctx.ECDH.HASH_TYPE;

  const C = [];
  const D = [];

  ctx.ECDH.ECPSP_DSA(sha, G.rngGen, issuer_sk_Bytes, credStr, C, D);
  const issuedCredSig = [C, D];


  return {
    pk_cred_bytes: pk_cred_bytes,
    pk_client_bytes: pk_client_bytes,
    issuedCredSig: issuedCredSig,
  };
};

export const verifyCredSignature = (issuedCred, pk_issuer_bytes) => {
  const {
    pk_cred_bytes, pk_client_bytes, issuedCredSig,
  } = issuedCred; // object destructuring

  const reducer = (acc, cur) => acc + cur;

  const credStr =
    pk_client_bytes.reduce(reducer) + // client's key
    pk_cred_bytes.reduce(reducer); // cred's pk

  const sha = ctx.ECDH.HASH_TYPE;

  const [C, D] = issuedCredSig;

  return ctx.ECDH.ECPVP_DSA(sha, pk_issuer_bytes, credStr, C, D) === 0;
};
