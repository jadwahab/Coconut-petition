import express from 'express';
import bodyParser from 'body-parser';
import { getBalance, changeBalance } from '../utils/DatabaseManager';
import { DEBUG, FAKE_BALANCE } from '../config/appConfig';
import { ISSUE_STATUS } from '../config/constants';
import { sig_skBytes, sig_pkBytes } from '../config/KeySetup';
import { verifyRequestSignature, verifyRequestProofOfCredSecret } from '../../CredRequest';
import { getIssuedCred } from '../../IssuedCred';

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

  // Verify whether request signature is legit:
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

  const issuerStr = sig_pkBytes.join('');

  // Verify whether request proof of knowledge is legit:
  const isProofValid = verifyRequestProofOfCredSecret(
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
        status: ISSUE_STATUS.error_proof,
      });
    return;
  }

// Issuer finally signs the credential
  const issuedCred = getIssuedCred(
    coin_request.pk_coin_bytes,
    coin_request.pk_client_bytes,
    sig_skBytes,
  );

  if (DEBUG) {
    console.log(ISSUE_STATUS.success);
  }
  const t1 = new Date().getTime();
  console.log('Issueance request took: ', t1 - t0);
  res.status(200)
    .json({
      coin: issuedCred,
      status: ISSUE_STATUS.success,
    });
});

export default router;
