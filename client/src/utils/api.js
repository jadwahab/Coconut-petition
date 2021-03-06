import fetch from 'isomorphic-fetch';
import { ctx, DEBUG, ISSUE_STATUS, params } from '../config';
import ElGamal from '../../lib/ElGamal';
import { getSimplifiedProof, getSimplifiedSignature, getSimplifiedMPCP, 
  getBytesMPVP, getBytesVotes } from '../../lib/BytesConversion';
import { getCredRequestObject } from '../../lib/CredRequest';
import { publicKeys } from '../cache';

// auxiliary, mostly for testing purposes to simulate delays
export function wait(t) {
  return new Promise(r => setTimeout(r, t));
}

export const getPublicKey = async (server) => {
  if (DEBUG) {
    console.log(`Sending request to get public key of ${server}`);
  }
  try {
    let response = await fetch(`http://${server}/pk`);
    response = await response.json();
    const pkBytes = response.pk;
    // due to the way they implemented ECDSA, we do not need to convert it
    return pkBytes;
  } catch (err) {
    console.log(err);
    console.warn(`Call to ${server} was unsuccessful`);
    return null;
  }
};

export async function getSigningAuthorityPublicKey(server) {
  const publicKey = [];
  if (DEBUG) {
    console.log(`Sending request to get public key of ${server}`);
  }
  try {
    let response = await fetch(`http://${server}/pk`);
    response = await response.json();
    const pkBytes = response.pk;
    const [gBytes, XBytes, YBytes] = pkBytes;
    publicKey.push(ctx.ECP2.fromBytes(gBytes));
    publicKey.push(ctx.ECP2.fromBytes(XBytes));
    publicKey.push(ctx.ECP2.fromBytes(YBytes));

  } catch (err) {
    console.log(err);
    console.warn(`Call to ${server} was unsuccessful`);
  }
  return publicKey;
}

export async function getCred(sk_cred, pk_cred, pk_client, sk_client, issuingServer) {
  const [G, o, g1, g2, e] = params;

  // for some reason we have no cached pk, lets try to get it
  if (publicKeys[issuingServer] == null || publicKeys[issuingServer].length <= 0) {
    const publicKey = await getPublicKey(issuingServer);
    publicKeys[issuingServer] = publicKey;

    // the call failed
    if (publicKeys[issuingServer] == null || publicKeys[issuingServer].length <= 0) {
      console.warn(ISSUE_STATUS.error_server);
      return null;
    }
  }

  const issuingServerStr = publicKeys[issuingServer].join('');

  const credRequestObject =
    getCredRequestObject(sk_cred, pk_cred, pk_client, sk_client, issuingServerStr);

  let issuedCred;
  let issuance_status;

  if (DEBUG) {
    console.log(`Calling ${issuingServer} to get a cred`);
  }
  try {
    let response = await
      fetch(`http://${issuingServer}/getcred`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          cred_request: credRequestObject,
        }),
      });
    response = await response.json();
    issuedCred = response.cred;
    issuance_status = response.status;
  } catch (err) {
    console.log(err);
    console.warn(`Call to ${issuingServer} was unsuccessful`);
  }

  if (issuance_status === ISSUE_STATUS.success) {
    // return [issuedCred, cred_id];
    return issuedCred;
  } else if (issuance_status != null) {
    console.warn(issuance_status);
  } else {
    console.warn(ISSUE_STATUS.error_server);
  }
  return null;
}

export async function checkIfAlive(server) {
  let isAlive = false;
  if (DEBUG) {
    console.log(`Checking status of ${server}`);
  }
  try {
    let response = await fetch(`http://${server}/status`);
    response = await response.json();
    isAlive = response.alive;
  } catch (err) {
    console.log(err);
    console.warn(`Call to ${server} was unsuccessful`);
  }
  return isAlive;
}

export async function signCred(server, signingCred, ElGamalPK) {
  let signature = null;
  if (DEBUG) {
    console.log('Compressed cred to sign: ', signingCred);
  }

  if (publicKeys[server] == null || publicKeys[server].length <= 0) {
    if (DEBUG) {
      console.log(`${server} wasn't queried before. We need to get its PK first.`);
    }
    const publicKey = await getSigningAuthorityPublicKey(server);
    publicKeys[server] = publicKey;
  } else if (DEBUG) {
    console.log(`${server} was queried before. Its PK is:`);
    console.log(publicKeys[server]);
  }
  if (DEBUG) {
    console.log(`Sending signing query to ${server}`);
  }

  try {
    let response = await
      fetch(`http://${server}/blindsign`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          cred: signingCred,
          ElGamalPKBytes: ElGamal.getPKBytes(ElGamalPK),
        }),
      });
    response = await response.json();

    // since the call was successful, recreate the objects from bytes representations
    const [hBytes, [enc_sig_a_Bytes, enc_sig_b_Bytes]] = response.signature;

    // we need to recreate those from bytes representations to aggregate them
    const h = ctx.ECP.fromBytes(hBytes);
    const enc_sig_a = ctx.ECP.fromBytes(enc_sig_a_Bytes);
    const enc_sig_b = ctx.ECP.fromBytes(enc_sig_b_Bytes);

    signature = [h, [enc_sig_a, enc_sig_b]];
  } catch (err) {
    console.warn(err);
    console.warn(`Call to ${server} was unsuccessful`);
  }
  return signature;
}

export async function voteCred(MPCP_output, signature, server, petitionID, enc_votes, MPVP_output) {
  const simplifiedMPCP = getSimplifiedMPCP(MPCP_output);
  const simplifiedSignature = getSimplifiedSignature(signature);
  const MPVP_bytes = getBytesMPVP(MPVP_output);
  const votes_bytes = getBytesVotes(enc_votes);

  const sent_obj = {
    MPCP: simplifiedMPCP,
    signature: simplifiedSignature,
    petitionID: petitionID,
    MPVP: MPVP_bytes,
    votes: votes_bytes,
  };

  if (DEBUG) {
    console.log('Sending ShowBlingSign output');
    console.log(sent_obj);
  }

  let success = false;
  let error_msg;
  try {
    let response = await
      fetch(`http://${server}/vote`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          MPCP: simplifiedMPCP,
          signature: simplifiedSignature,
          petitionID: petitionID,
          MPVP: MPVP_bytes,
          votes: votes_bytes,
        }),
      });
    response = await response.json();
    success = response.success;
    error_msg = response.error_msg;
  } catch (err) {
    console.warn(err);
    console.warn(`Call to petitionOwner ${server} was unsuccessful`);
  }
  return [success, error_msg];
}
