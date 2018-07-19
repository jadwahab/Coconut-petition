import { ctx, params } from '../src/config';

const MIN_TTL_H = 12;

const getHourTimeDifference = (date1, date2) => {
  const difference = (date1.getTime() - date2.getTime()) / (1000 * 60 * 60);
  return Math.abs(Math.round(difference));
};

const getTimeToLive = () => {
  const currentTime = new Date();
  const endOfDayTime = new Date(
    currentTime.getFullYear(),
    currentTime.getMonth(),
    currentTime.getDate(),
    23, 59, 59, 999,
  );

  let timeToLive;
  const hoursUntilEndOfDay = getHourTimeDifference(currentTime, endOfDayTime);
  // if it's less than MIN hours until end of day, set TTL to end of day plus 24h
  if (hoursUntilEndOfDay < MIN_TTL_H) {
    timeToLive = endOfDayTime.getTime() + 1 + (1000 * 60 * 60 * 24);
  } else {
    timeToLive = endOfDayTime.getTime() + 1; // otherwise just set it to end of day
  }

  return timeToLive;
};

export const getIssuedCoin = (pk_coin_bytes, value, pk_client_bytes, issuer_sk_Bytes) => {
  const [G, o, g1, g2, e] = params;

  const ttl = getTimeToLive();

  // same reasoning as with CoinRequest
  const reducer = (acc, cur) => acc + cur;

  const coinStr =
    pk_client_bytes.reduce(reducer) + // client's key
    value.toString() + // coin's value
    pk_coin_bytes.reduce(reducer) + // coin's pk
    ttl.toString();

  const sha = ctx.ECDH.HASH_TYPE;

  const C = [];
  const D = [];

  ctx.ECDH.ECPSP_DSA(sha, G.rngGen, issuer_sk_Bytes, coinStr, C, D);
  const issuedCoinSig = [C, D];


  return {
    pk_coin_bytes: pk_coin_bytes,
    ttl: ttl,
    value: value,
    pk_client_bytes: pk_client_bytes,
    issuedCoinSig: issuedCoinSig,
  };
};

export const verifyCoinSignature = (issuedCoin, pk_issuer_bytes) => {
  const {
    pk_coin_bytes, ttl, value, pk_client_bytes, issuedCoinSig,
  } = issuedCoin; // object destructuring

  const reducer = (acc, cur) => acc + cur;

  const coinStr =
    pk_client_bytes.reduce(reducer) + // client's key
    value.toString() + // coin's value
    pk_coin_bytes.reduce(reducer) + // coin's pk
    ttl.toString();

  const sha = ctx.ECDH.HASH_TYPE;

  const [C, D] = issuedCoinSig;

  return ctx.ECDH.ECPVP_DSA(sha, pk_issuer_bytes, coinStr, C, D) === 0;
};
