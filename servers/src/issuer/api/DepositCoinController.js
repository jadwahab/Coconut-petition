import express from 'express';
import bodyParser from 'body-parser';
import { checkUsedId, insertUsedId, changeBalance } from '../utils/DatabaseManager';
import { ctx, merchant, params, signingServers } from '../../globalConfig';
import { DEBUG } from '../config/appConfig';
import { fromBytesMPCP, verifyProofOfSecret, getSigningAuthorityPublicKey,
  getPublicKey, verify_proof_credentials_petition } from '../../auxiliary';
import CoinSig from '../../CoinSig';
import { publicKeys } from '../cache';

const router = express.Router();


router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());


router.post('/', async (req, res) => {
  const t0 = new Date().getTime();
  if (DEBUG) {
    console.log('Deposit coin post');
  }

  const [hBytes, sigBytes] = req.body.signature;
  const simplifiedProof = req.body.proof;

  const MPCP_output = fromBytesMPCP(simplifiedProof);
  const h = ctx.ECP.fromBytes(hBytes);
  const sig = ctx.ECP.fromBytes(sigBytes);


  if (publicKeys[merchant] == null || publicKeys[merchant].length <= 0) {
    const merchantPK = await getPublicKey(merchant);
    publicKeys[merchant] = merchantPK;
  }

  const merchantStr = publicKeys[merchant].join('');

  const signingAuthoritiesPublicKeys = Object.entries(publicKeys)
    .filter(entry => signingServers.includes(entry[0]))
    .map(entry => entry[1]);

  // if all keys of signing authorities were cached, we can assume that the aggregate was also cached
  let aggregatePublicKey;
  if (signingAuthoritiesPublicKeys.length !== signingServers.length) {
    await Promise.all(signingServers.map(async (server) => {
      try {
        const publicKey = await getSigningAuthorityPublicKey(server);
        publicKeys[server] = publicKey;
        signingAuthoritiesPublicKeys.push(publicKey);
      } catch (err) {
        console.warn(err);
      }
    }));
    aggregatePublicKey = CoinSig.aggregatePublicKeys(params, signingAuthoritiesPublicKeys);

    publicKeys['Aggregate'] = aggregatePublicKey;
  } else {
    aggregatePublicKey = publicKeys['Aggregate'];
  }

  const isProofValid = verify_proof_credentials_petition(params, aggregatePublicKey, [h, sig], MPCP_output, merchantStr);
  if (DEBUG) {
    console.log(`Was credntial proof valid: ${isProofValid}`);
  }

  if (!isProofValid) {
    if (DEBUG) {
      console.log('Credntial proof was invalid.');
    }
    res.status(200)
      .json({ success: false });
    return;
  }

  // // now finally check if the coin wasn't already spent
  // const wasCoinAlreadySpent = await checkUsedId(id);
  // if (DEBUG) {
  //   console.log(`Was coin already spent: ${wasCoinAlreadySpent}`);
  // }
  //
  // if (isProofValid && !wasCoinAlreadySpent && isSignatureValid) {
  //   await insertUsedId(id);
  //   // await changeBalance(publicKeys[merchant], coinAttributes.value);
  // }


  // EDIT: send to issuer to isert used zeta

  const t1 = new Date().getTime();
  console.log('Deposit took: ', t1 - t0);

  res.status(200)
    .json({
      success: true,
    });
});

export default router;
