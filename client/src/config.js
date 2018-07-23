import CTX from '../lib/Milagro-Crypto-Library/ctx';
import CoinSig from '../lib/CoinSig';

export const DEBUG = true;
export const DETAILED_DEBUG = true;

export const signingServers = (process.env.NODE_ENV === 'production') ? [
  '35.176.12.245:3000',
  '35.177.49.8:3000',
  '35.177.54.142:3000',
] : [
  '127.0.0.1:3000',
  '127.0.0.1:3001',
  '127.0.0.1:3002',
];

export const merchant = (process.env.NODE_ENV === 'production') ? '35.178.0.223:3001' : '127.0.0.1:4000';
export const issuer = (process.env.NODE_ENV === 'production') ? '35.178.15.103:3002' : '127.0.0.1:5000';

export const ctx = new CTX('BN254');
export const params = CoinSig.setup();

const COIN_STATUS_UNCREATED = 'Ungenerated';
const COIN_STATUS_CREATED = 'Generated';
const COIN_STATUS_SIGNED = 'Signed';
const COIN_STATUS_SPENT = 'Spent';
const COIN_STATUS_SPENDING = 'Spending';
const COIN_STATUS_ERROR = 'Error';

export const COIN_STATUS = {
  uncreated: COIN_STATUS_UNCREATED,
  created: COIN_STATUS_CREATED,
  signed: COIN_STATUS_SIGNED,
  spent: COIN_STATUS_SPENT,
  spending: COIN_STATUS_SPENDING,
  error: COIN_STATUS_ERROR,
};

const BUTTON_COIN_STATUS_GET = 'Get Credential';
const BUTTON_COIN_STATUS_SIGN = 'Sign Credential';
const BUTTON_COIN_STATUS_SPEND = 'Spend Coin';
const BUTTON_COIN_STATUS_SPENT = 'Coin was Spent';
const BUTTON_COIN_STATUS_SPENDING_IN_PROGRESS = 'Spending...';
const BUTTON_COIN_STATUS_ERROR = 'Error';
const BUTTON_COIN_STATUS_READY = 'Randomize Credential';

export const BUTTON_COIN_STATUS = {
  get: BUTTON_COIN_STATUS_GET,
  sign: BUTTON_COIN_STATUS_SIGN,
  spend: BUTTON_COIN_STATUS_SPEND,
  spent: BUTTON_COIN_STATUS_SPENT,
  spending: BUTTON_COIN_STATUS_SPENDING_IN_PROGRESS,
  error: BUTTON_COIN_STATUS_ERROR,
  ready: BUTTON_COIN_STATUS_READY,
};

const SERVER_TYPE_SA = 'Signing Authority';
const SERVER_TYPE_MERCHANT = 'Merchant';
const SERVER_TYPE_ISSUER = 'Issuer';

export const SERVER_TYPES = {
  signing: SERVER_TYPE_SA,
  merchant: SERVER_TYPE_MERCHANT,
  issuer: SERVER_TYPE_ISSUER,
};

const SERVER_STATUS_UP = 'Server is alive';
const SERVER_STATUS_DOWN = 'Server is down';
const SERVER_STATUS_CHECK = 'Checking server status...';

export const SERVER_STATUS = {
  alive: SERVER_STATUS_UP,
  down: SERVER_STATUS_DOWN,
  loading: SERVER_STATUS_CHECK,
};

const ISSUE_ERROR_NOT_ENOUGH_BALANCE = 'Balance was not high enough to issue the coin';
const ISSUE_ERROR_PROOF_INVALID = 'Proof of secret was invalid';
const ISSUE_SUCCESS = 'Credential was successfully issued';
const ISSUE_ERROR_INVALID_SIGNATURE = 'The signature on request was invalid';
const ISSUE_ERROR_SERVER_DOWN = 'The Issuance server seems to be down';

export const ISSUE_STATUS = {
  error_balance: ISSUE_ERROR_NOT_ENOUGH_BALANCE,
  error_proof: ISSUE_ERROR_PROOF_INVALID,
  success: ISSUE_SUCCESS,
  error_signature: ISSUE_ERROR_INVALID_SIGNATURE,
  error_server: ISSUE_ERROR_SERVER_DOWN,
};
