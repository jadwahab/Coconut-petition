import fetch from 'isomorphic-fetch';
import { ctx, DEBUG, ISSUE_STATUS, params } from '../config';
import { getSimplifiedProof, getSimplifiedSignature, getRandomNumber, getSimplifiedMPCP } from './helpers';
import ElGamal from '../../lib/ElGamal';
import { getCoinRequestObject } from '../../lib/CoinRequest';
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

export async function getCoin(sk_coin, pk_coin, pk_client, sk_client, issuingServer) {
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

  const coinRequestObject =
    getCoinRequestObject(sk_coin, pk_coin, pk_client, sk_client, issuingServerStr);

  let issuedCoin;
  let issuance_status;

  if (DEBUG) {
    console.log(`Calling ${issuingServer} to get a coin`);
  }
  try {
    let response = await
      fetch(`http://${issuingServer}/getcoin`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          coin_request: coinRequestObject,
        }),
      });
    response = await response.json();
    issuedCoin = response.coin;
    issuance_status = response.status;
  } catch (err) {
    console.log(err);
    console.warn(`Call to ${issuingServer} was unsuccessful`);
  }

  if (issuance_status === ISSUE_STATUS.success) {
    // return [issuedCoin, coin_id];
    return issuedCoin;
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

export async function signCoin(server, signingCoin, ElGamalPK) {
  let signature = null;
  if (DEBUG) {
    console.log('Compressed coin to sign: ', signingCoin);
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
          coin: signingCoin,
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

// ... we can't send v because it would link us to issuance, we just send ttl, id, proof of x (on aX3) and sig
// pkX = aX3^x
export async function spendCoin(MPCP_output, signature, server, petitionID) {
  const simplifiedMPCP = getSimplifiedMPCP(MPCP_output);
  const simplifiedSignature = getSimplifiedSignature(signature);

  if (DEBUG) {
    console.log('Sending ShowBlingSign output');
  }

  let success = false;
  try {
    let response = await
      fetch(`http://${server}/spend`, {
        method: 'POST',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          proof: simplifiedMPCP,
          signature: simplifiedSignature,
          petitionID: petitionID,
        }),
      });
    response = await response.json();
    success = response.success;
  } catch (err) {
    console.warn(err);
    console.warn(`Call to petitionOwner ${server} was unsuccessful`); // EDIT:
  }
  return success;
}
