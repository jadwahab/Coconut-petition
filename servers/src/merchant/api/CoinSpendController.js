import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'isomorphic-fetch';
import { ctx, params, signingServers, issuer } from '../../globalConfig';
import CoinSig from '../../CoinSig';
import { DEBUG } from '../config/appConfig';
import { fromBytesProof, verifyProofOfSecret, getSigningAuthorityPublicKey } from '../../auxiliary';
import { sig_pkBytes } from '../config/KeySetup';
import { publicKeys } from '../cache';

const router = express.Router();

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

const checkDoubleSpend = async (id, server) => {
  const id_bytes = [];
  id.toBytes(id_bytes);
  try {
    let response = await
      fetch(`http://${server}/checkid`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          id: id_bytes,
        }),
      });
    response = await response.json();
    return response.wasIdUsed;
  } catch (err) {
    console.log(err);
    console.warn(`Call to ${server} was unsuccessful`);
    return true; // if call was unsuccessful assume coin was already spent
  }
};

const depositCoin = async (coinAttributes, simplifiedProof, sigBytes, pkXBytes, server) => {
  try {
    let response = await
      fetch(`http://${server}/depositcoin`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          coinAttributes: coinAttributes,
          proof: simplifiedProof,
          signature: sigBytes,
          pkXBytes: pkXBytes,
        }),
      });
    response = await response.json();
    const success = response.success;
    return success;
  } catch (err) {
    console.log(err);
    console.warn(`Call to ${server} was unsuccessful`);
    return false; // if call was unsuccessful assume deposit failed
  }
};

router.post('/', async (req, res) => {
  const t0 = new Date().getTime();
  const client_address = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

  if (DEBUG) {
    console.log('spend post from ', client_address);
  }

  let responseStatus = -1;
  let success = false;

  try {
    const coinAttributes = req.body.coinAttributes;
    const simplifiedProof = req.body.proof;
    const pkXBytes = req.body.pkX;

    const proofOfSecret = fromBytesProof(simplifiedProof);
    const pkX = ctx.ECP2.fromBytes(pkXBytes);
    const id = ctx.BIG.fromBytes(coinAttributes.idBytes);

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

    // just check validity of the proof and double spending, we let issuer verify the signature
    // successful verification of the proof assures the coin was supposed to be used in that transaction
    const merchantStr = sig_pkBytes.join('');
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

    // now finally check if the coin wasn't already spent
    const wasCoinAlreadySpent = await checkDoubleSpend(id, issuer);
    if (DEBUG) {
      console.log(`Was coin already spent: ${wasCoinAlreadySpent}`);
    }

    // we don't need to create byte representations of all objects because we already have them
    const wasCoinDeposited = await depositCoin(coinAttributes, simplifiedProof, req.body.signature, pkXBytes, issuer);

    responseStatus = 200;
    success = isProofValid && !wasCoinAlreadySpent && wasCoinDeposited;
    if (DEBUG) {
      console.log(`Was coin successfully spent: ${success}`);
    }
  } catch (err) {
    console.warn(err);
    responseStatus = 400;
  }
  const t1 = new Date().getTime();
  console.log('Request took: ', t1 - t0);

  res.status(responseStatus)
    .json({ success: success });
});

export default router;
