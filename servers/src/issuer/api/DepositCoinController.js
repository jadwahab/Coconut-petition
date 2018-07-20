import express from 'express';
import bodyParser from 'body-parser';
import { checkUsedId, insertUsedId, changeBalance } from '../utils/DatabaseManager';
import { ctx, merchant, params, signingServers } from '../../globalConfig';
import { DEBUG } from '../config/appConfig';
import { fromBytesProof, verifyProofOfSecret, getSigningAuthorityPublicKey, getPublicKey } from '../../auxiliary';
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

  const coinAttributes = req.body.coinAttributes;
  const simplifiedProof = req.body.proof;
  const [hBytes, sigBytes] = req.body.signature;
  const pkXBytes = req.body.pkXBytes;

  const proofOfSecret = fromBytesProof(simplifiedProof);
  const h = ctx.ECP.fromBytes(hBytes);
  const sig = ctx.ECP.fromBytes(sigBytes);
  const pkX = ctx.ECP2.fromBytes(pkXBytes);
  const id = ctx.BIG.fromBytes(coinAttributes.idBytes);

  // start by checking if the coin is still valid
  if (coinAttributes.ttl < new Date().getTime()) {
    if (DEBUG) {
      console.log('Coin has expired, no further checks will be made.');
    }
    res.status(200)
      .json({ success: false });
    return;
  }

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

  // aggregatePublicKey is [ag, aX0, aX1, aX2, aX3, aX4];
  const aX3 = aggregatePublicKey[4];

  if (publicKeys[merchant] == null || publicKeys[merchant].length <= 0) {
    const merchantPK = await getPublicKey(merchant);
    publicKeys[merchant] = merchantPK;
  }

  const merchantStr = publicKeys[merchant].join('');
  const isProofValid = verifyProofOfSecret(params, pkX, proofOfSecret, merchantStr, aX3);

  if (DEBUG) {
    console.log(`Was proof of knowledge of secret valid: ${isProofValid}`);
  }
  if (!isProofValid) {
    if (DEBUG) {
      console.log('Proof was invalid, no further checks will be made.');
    }
    res.status(200)
      .json({ success: false });
    return;
  }

  const isSignatureValid = CoinSig.verifyMixedBlindSign(params, aggregatePublicKey, coinAttributes, [h, sig], id, pkX);
  if (DEBUG) {
    console.log(`Was signature valid: ${isSignatureValid}`);
  }

  if (!isSignatureValid) {
    if (DEBUG) {
      console.log('Signature was invalid.');
    }
    res.status(200)
      .json({ success: false });
    return;
  }

  // now finally check if the coin wasn't already spent
  const wasCoinAlreadySpent = await checkUsedId(id);
  if (DEBUG) {
    console.log(`Was coin already spent: ${wasCoinAlreadySpent}`);
  }

  if (isProofValid && !wasCoinAlreadySpent && isSignatureValid) {
    await insertUsedId(id);
    // await changeBalance(publicKeys[merchant], coinAttributes.value);
  }

  const t1 = new Date().getTime();
  console.log('Deposit took: ', t1 - t0);

  res.status(200)
    .json({
      success: true,
    });
});

export default router;
