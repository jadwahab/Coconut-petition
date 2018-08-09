import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'isomorphic-fetch';
import { ctx, params, signingServers, issuer } from '../../globalConfig';
import CredSig from '../../CredSig';
import { DEBUG } from '../config/appConfig';
import { getSigningAuthorityPublicKey } from '../../auxiliary';
import { fromBytesMPCP, fromBytesMPVP, fromBytesVotes, getBytesVotes } from '../../BytesConversion';
import { verify_proof_credentials_petition, verify_proof_vote_petition } from '../../Proofs';
import { sig_pkBytes } from '../config/KeySetup';
import { publicKeys } from '../cache';

const storage = [];

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
//     return true; // if call was unsuccessful assume cred was already spent
//   }
// };

// const depositCred = async (credAttributes, simplifiedProof, sigBytes, pkXBytes, server) => {
//   try {
//     let response = await
//       fetch(`http://${server}/depositcred`, {
//         method: 'POST',
//         mode: 'cors',
//         headers: {
//           'Content-Type': 'application/json',
//         },
//         body: JSON.stringify({
//           credAttributes: credAttributes,
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

const getSigningAuthorityElGamal = async (server) => {
  let pkElGamal;
  try {
    let response = await fetch(`http://${server}/pk`);
    response = await response.json();
    const pkElGamalBytes = response.pkElGamal;
    pkElGamal = ctx.ECP.fromBytes(pkElGamalBytes);
  } catch (err) {
    console.log(err);
    console.warn(`Call to ${server} was unsuccessful`);
  }
  return pkElGamal;
};

const sendThresholdDecryption = async (server, enc_votes, decIndex) => {
  try {
    const response = await
    fetch(`http://${server}/thresholddecrypt`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        votes_bytes: getBytesVotes(enc_votes),
        decIndex: decIndex,
      }),
    });
    if (response.status === 200) {
      console.log(`Successfully sent threshold decryption to ${server}`);
      return true;
    }
    console.log(`Threshold decryption to ${server} failed`);
    return false;
  } catch (err) {
    console.warn(err);
    console.warn(`Call to ${server} was unsuccessful`);
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
    const simplifiedMPCP = req.body.MPCP;
    const [hBytes, sigBytes] = req.body.signature;
    const petitionID = req.body.petitionID;
    const MPVP_bytes = req.body.MPVP;
    const votes_bytes = req.body.votes;

    const MPCP_output = fromBytesMPCP(simplifiedMPCP);
    const h = ctx.ECP.fromBytes(hBytes);
    const sig = ctx.ECP.fromBytes(sigBytes);
    const sigma = [h, sig];
    const MPVP_output = fromBytesMPVP(MPVP_bytes);
    const enc_votes = fromBytesVotes(votes_bytes);

    // VPCP
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
    // successful verification of the proof assures the cred was supposed to be used in that transaction
    const isProofValid = verify_proof_credentials_petition(params, aggregatePublicKey, 
      sigma, MPCP_output, petitionOwner, petitionID);
    
    if (DEBUG) {
      console.log(`Was credntial proof valid: ${isProofValid}`);
    }
    if (!isProofValid) {
      if (DEBUG) {
        console.log('Proof was invalid, no further checks will be made.');
      }
      res.status(200)
        .json({ success: false, error_msg: 'sig' });
      return;
    }

    // VPVP:
    const signingAuthoritiesElGamal = [];
    await Promise.all(signingServers.map(async (server) => {
      try {
        const publicKey = await getSigningAuthorityElGamal(server);
        signingAuthoritiesElGamal.push(publicKey);
      } catch (err) {
        console.warn(err);
      }
    }));
    const aggregateElGamal = CredSig.aggregateElGamalPublicKeys(params, signingAuthoritiesElGamal);

    const isVoteValid = verify_proof_vote_petition(params, aggregateElGamal, MPVP_output, enc_votes[0]);
    
    if (DEBUG) {
      console.log(`Was vote proof valid: ${isVoteValid}`);
    }
    if (!isVoteValid) {
      if (DEBUG) {
        console.log('Proof was invalid, no further checks will be made.');
      }
      res.status(200)
        .json({ success: false, error_msg: 'sig' });
      return;
    }
    
    // // now finally check if the cred wasn't already spent
    // const wasCredAlreadySpent = await checkDoubleSpend(id, issuer);
    // if (DEBUG) {
    //   console.log(`Was cred already spent: ${wasCredAlreadySpent}`);
    // }
    //
    // // we don't need to create byte representations of all objects because we already have them
    // const wasCredDeposited = await depositCred(credAttributes, simplifiedProof, req.body.signature, pkXBytes, issuer);
    
    // get a new list of only zetas with that specific petitionID
    const storagetemp = storage.filter(zid => zid.id === petitionID);

    if (DEBUG) {
      console.log(`Petition ${petitionID} already has ${storagetemp.length} votes`);
    }
    
    // const [kappa, nu, zeta, pi_v] = MPCP_output;
    const zetaIdVote = {
      id: petitionID,
      zeta: MPCP_output[2],
      enc_votes: enc_votes,
    };

    // check if this user ALREADY voted for this petition
    if (storagetemp.length > 0) {
      for (let i = 0; i < storagetemp.length; i++) {
        const isUsed = zetaIdVote.zeta.equals(storagetemp[i].zeta);
        if (isUsed) {
          if (DEBUG) {
            console.log('Already voted for this petition');
          }
          res.status(200)
            .json({ success: false, error_msg: 'used' });
          return;
        }
      }
    }

    storage.push(zetaIdVote);
    storagetemp.push(zetaIdVote);

    // check if 2 people voted
    if (storagetemp.length === 4) {
      const [enc_v, enc_v_not] = storagetemp[0].enc_votes;
      // return [a, b, k]
      const [a_enc_v, b_enc_v, kv0] = enc_v;
      const [a_enc_v_not, b_enc_v_not, kv1] = enc_v_not;

      for (let i = 1; i < storagetemp.length; i++) {
        const [temp_enc_v, temp_enc_v_not] = storagetemp[i].enc_votes;
        a_enc_v.add(temp_enc_v[0]);
        b_enc_v.add(temp_enc_v[1]);

        a_enc_v_not.add(temp_enc_v_not[0]);
        b_enc_v_not.add(temp_enc_v_not[1]);
      } // end for

      a_enc_v.affine();
      b_enc_v.affine();
      a_enc_v_not.affine();
      b_enc_v_not.affine();

      const enc_votes_total = [[a_enc_v, b_enc_v], [a_enc_v_not, b_enc_v_not]]

      const decIndex = signingServers.length - 1;
      
      const sentthreshdec = await
      sendThresholdDecryption(signingServers[decIndex], enc_votes_total, decIndex);

      if (DEBUG) {
        if (!sentthreshdec) {
          console.log('Error in sending the threshold decryption');
        }
      }
    }
    if (storagetemp.length > 4) {
      if (DEBUG) {
        console.log('Petition ended');
      }
      res.status(200)
        .json({ success: false, error_msg: 'ended' });
      return;
    }

    responseStatus = 200;
    // EDIT: add sentthreshdec here to success
    success = isProofValid && isVoteValid;
    if (DEBUG) {
      console.log(`Was credential successfully used to vote: ${success}`);
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
    .json({ success: success, error_msg: 'none' });
});

export default router;
