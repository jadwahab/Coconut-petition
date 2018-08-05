import CTX from './lib/Milagro-Crypto-Library/ctx';
import CoinSig from './CoinSig';

export const signingServers = (process.env.NODE_ENV === 'production') ? [
  '35.176.12.245:3000',
  '35.177.49.8:3000',
  '35.177.54.142:3000',
] : [
  '127.0.0.1:3000',
  '127.0.0.1:3001',
  '127.0.0.1:3002',
];

export const petitionOwner = (process.env.NODE_ENV === 'production') ? '35.178.0.223:3001' : '127.0.0.1:4000';
export const issuer = (process.env.NODE_ENV === 'production') ? '35.178.15.103:3002' : '127.0.0.1:5000';

export const ctx = new CTX('BN254');
export const params = CoinSig.setup();
export const power = new ctx.BIG(2);
