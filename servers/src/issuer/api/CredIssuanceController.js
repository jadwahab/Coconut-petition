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
    console.log('>POST Call to getcred');
  }
  const sourceIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress; // just for purpose of debugging
  if (DEBUG) {
    console.log('Request came from', sourceIp);
  }

  const cred_request = req.body.cred_request;

  // Verify whether request signature is legit:
  const isSignatureValid = verifyRequestSignature(cred_request);
  if (!isSignatureValid) {
    if (DEBUG) {
      console.log('Error in issuing cred', ISSUE_STATUS.error_signature);
    }
    res.status(200)
      .json({
        cred: null,
        status: ISSUE_STATUS.error_signature,
      });
    return;
  }

  const issuerStr = sig_pkBytes.join('');

  // Verify whether request proof of knowledge is legit:
  const isProofValid = verifyRequestProofOfCredSecret(
    cred_request.proof_bytes,
    cred_request.pk_cred_bytes,
    issuerStr,
  );

  if (!isProofValid) {
    if (DEBUG) {
      console.log('Error in issuing cred', ISSUE_STATUS.error_proof);
    }
    res.status(200)
      .json({
        cred: null,
        status: ISSUE_STATUS.error_proof,
      });
    return;
  }

// Issuer finally signs the credential
  const issuedCred = getIssuedCred(
    cred_request.pk_cred_bytes,
    cred_request.pk_client_bytes,
    sig_skBytes,
  );

  if (DEBUG) {
    console.log(ISSUE_STATUS.success);
  }
  const t1 = new Date().getTime();
  console.log('Issueance request took: ', t1 - t0);
  res.status(200)
    .json({
      cred: issuedCred,
      status: ISSUE_STATUS.success,
    });
});

export default router;
