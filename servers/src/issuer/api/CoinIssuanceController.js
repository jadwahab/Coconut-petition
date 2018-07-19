import express from 'express';
import bodyParser from 'body-parser';
import { getBalance, changeBalance } from '../utils/DatabaseManager';
import { DEBUG, FAKE_BALANCE } from '../config/appConfig';
import { ISSUE_STATUS } from '../config/constants';
import { sig_skBytes, sig_pkBytes } from '../config/KeySetup';
import { verifyRequestSignature, verifyRequestProofOfCoinSecret } from '../../CoinRequest';
import { getIssuedCoin } from '../../IssuedCoin';

const router = express.Router();

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

// don't cache client's pk as he sends it every request
// and in principle there can be an arbitrary number of clients
router.post('/', async (req, res) => {
  const t0 = new Date().getTime();
  if (DEBUG) {
    console.log('POST Call to getcoin');
  }
  const sourceIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress; // just for purpose of debugging
  if (DEBUG) {
    console.log('Request came from', sourceIp);
  }

  const coin_request = req.body.coin_request;
  // start by checking whether requested coin value is legit (DONT RELY ON CLIENT-SIDE VALIDATION)
  if (!Number.isInteger(coin_request.value)) {
    res.status(200)
      .json({
        coin: null,
        status: ISSUE_STATUS.error_balance,
      });
    return;
  }

  // then verify whether request is legit:
  const isSignatureValid = verifyRequestSignature(coin_request);
  if (!isSignatureValid) {
    if (DEBUG) {
      console.log('Error in issuing coin', ISSUE_STATUS.error_signature);
    }
    res.status(200)
      .json({
        coin: null,
        status: ISSUE_STATUS.error_signature,
      });
    return;
  }
  let balance = await getBalance(coin_request.pk_client_bytes);
  if (DEBUG) {
    console.log('Balance of callee is', balance);
  }

  if (DEBUG || FAKE_BALANCE) {
    // this will only happen in debug mode to make it easier to test the system
    const cheat_balance = 1000.00;
    if (balance === -1) {
      await changeBalance(coin_request.pk_client_bytes, cheat_balance);
      balance = cheat_balance;
    }
  }

  if (balance < coin_request.value) {
    if (DEBUG) {
      console.log('Error in issuing coin', ISSUE_STATUS.error_balance);
    }
    res.status(200)
      .json({
        coin: null,
        status: ISSUE_STATUS.error_balance,
      });
    return;
  }
  const issuerStr = sig_pkBytes.join('');

  const isProofValid = verifyRequestProofOfCoinSecret(
    coin_request.proof_bytes,
    coin_request.pk_coin_bytes,
    issuerStr,
  );

  if (!isProofValid) {
    if (DEBUG) {
      console.log('Error in issuing coin', ISSUE_STATUS.error_proof);
    }
    res.status(200)
      .json({
        coin: null,
        id: null,
        status: ISSUE_STATUS.error_proof,
      });
    return;
  }
  const issuedCoin = getIssuedCoin(
    coin_request.pk_coin_bytes,
    coin_request.value,
    coin_request.pk_client_bytes,
    sig_skBytes,
  );

  await changeBalance(coin_request.pk_client_bytes, -coin_request.value);

  if (DEBUG) {
    console.log(ISSUE_STATUS.success);
  }
  const t1 = new Date().getTime();
  console.log('Issueance request took: ', t1 - t0);
  res.status(200)
    .json({
      coin: issuedCoin,
      status: ISSUE_STATUS.success,
    });
});

export default router;
