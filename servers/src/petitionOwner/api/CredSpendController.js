import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'isomorphic-fetch';
import { ctx, params, signingServers, issuer } from '../../globalConfig';
import CredSig from '../../CredSig';
import { DEBUG } from '../config/appConfig';
import { fromBytesMPCP, getSigningAuthorityPublicKey, verify_proof_credentials_petition } from '../../auxiliary';
import { sig_pkBytes } from '../config/KeySetup';
import { publicKeys } from '../cache';

const router = express.Router();

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

// const checkDoubleSpend = async (id, server) => {
//   const id_bytes = [];
//   id.toBytes(id_bytes);
//   try {
//     let response = await
//       fetch(`http://${server}/checkid`, {
//         method: 'POST',
//         mode: 'cors',
//         headers: {
//           'Content-Type': 'application/json',
//         },
//         body: JSON.stringify({
//           id: id_bytes,
//         }),
//       });
//     response = await response.json();
//     return response.wasIdUsed;
//   } catch (err) {
//     console.log(err);
//     console.warn(`Call to ${server} was unsuccessful`);
//     return true; // if call was unsuccessful assume coin was already spent
//   }
// };

// const depositCred = async (coinAttributes, simplifiedProof, sigBytes, pkXBytes, server) => {
//   try {
//     let response = await
//       fetch(`http://${server}/depositcoin`, {
//         method: 'POST',
//         mode: 'cors',
//         headers: {
//           'Content-Type': 'application/json',
//         },
//         body: JSON.stringify({
//           coinAttributes: coinAttributes,
//           proof: simplifiedProof,
//           signature: sigBytes,
//           pkXBytes: pkXBytes,
//         }),
//       });
//     response = await response.json();
//     const success = response.success;
//     return success;
//   } catch (err) {
//     console.log(err);
//     console.warn(`Call to ${server} was unsuccessful`);
//     return false; // if call was unsuccessful assume deposit failed
//   }
// };

router.post('/', async (req, res) => {
  const t0 = new Date().getTime();
  const client_address = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

  if (DEBUG) {
    console.log('spend post from ', client_address);
  }

  let responseStatus = -1;
  let success = false;

  try {
    const simplifiedMPCP = req.body.proof;
    const [hBytes, sigBytes] = req.body.signature;
    const petitionID = req.body.petitionID;

    const MPCP_output = fromBytesMPCP(simplifiedMPCP);
    const h = ctx.ECP.fromBytes(hBytes);
    const sig = ctx.ECP.fromBytes(sigBytes);
    const sigma = [h, sig];

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
      // aggregatePublicKey is [ag, aX, aY];
      aggregatePublicKey = CredSig.aggregatePublicKeys_array(params, signingAuthoritiesPublicKeys);

      publicKeys['Aggregate'] = aggregatePublicKey;
    } else {
      aggregatePublicKey = publicKeys['Aggregate'];
    }
    
    const petitionOwner = sig_pkBytes.join('');
    
    // just check validity of the proof and double spending, we let issuer verify the signature
    // successful verification of the proof assures the coin was supposed to be used in that transaction
    const isProofValid = CredSig.verify_proof_credentials_petition(params, aggregatePublicKey, 
      sigma, MPCP_output, petitionOwner, petitionID);
    
    if (DEBUG) {
      console.log(`Was credntial proof valid: ${isProofValid}`);
    }
    if (!isProofValid) {
      if (DEBUG) {
        console.log('Proof was invalid, no further checks will be made.');
      }
      res.status(200)
        .json({ success: false });
      return;
    }
    
    // // now finally check if the coin wasn't already spent
    // const wasCredAlreadySpent = await checkDoubleSpend(id, issuer);
    // if (DEBUG) {
    //   console.log(`Was coin already spent: ${wasCredAlreadySpent}`);
    // }
    //
    // // we don't need to create byte representations of all objects because we already have them
    // const wasCredDeposited = await depositCred(coinAttributes, simplifiedProof, req.body.signature, pkXBytes, issuer);
    
    responseStatus = 200;
    // success = isProofValid && !wasCredAlreadySpent && wasCredDeposited;
    success = isProofValid;
    if (DEBUG) {
      console.log(`Was credential successfully shown: ${success}`);
      if (success) {
        console.log(`Zeta shown for petitionID: ${petitionID}`);
        
      }
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
