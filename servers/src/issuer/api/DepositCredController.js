import express from 'express';
import bodyParser from 'body-parser';
import { checkUsedId, insertUsedId, changeBalance } from '../utils/DatabaseManager';
import { ctx, petitionOwner, params, signingServers } from '../../globalConfig';
import { DEBUG } from '../config/appConfig';
import { fromBytesMPCP, verifyProofOfSecret, getSigningAuthorityPublicKey,
  getPublicKey, verify_proof_credentials_petition } from '../../auxiliary';
import CredSig from '../../CredSig';
import { publicKeys } from '../cache';

const router = express.Router();


router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());


router.post('/', async (req, res) => {
  const t0 = new Date().getTime();
  if (DEBUG) {
    console.log('Deposit cred post');
  }

  const [hBytes, sigBytes] = req.body.signature;
  const simplifiedProof = req.body.proof;

  const MPCP_output = fromBytesMPCP(simplifiedProof);
  const h = ctx.ECP.fromBytes(hBytes);
  const sig = ctx.ECP.fromBytes(sigBytes);


  if (publicKeys[petitionOwner] == null || publicKeys[petitionOwner].length <= 0) {
    const petitionOwnerPK = await getPublicKey(petitionOwner);
    publicKeys[petitionOwner] = petitionOwnerPK;
  }

  const petitionOwnerStr = publicKeys[petitionOwner].join('');

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
    aggregatePublicKey = CredSig.aggregatePublicKeys(params, signingAuthoritiesPublicKeys);

    publicKeys['Aggregate'] = aggregatePublicKey;
  } else {
    aggregatePublicKey = publicKeys['Aggregate'];
  }

  const isProofValid = verify_proof_credentials_petition(params, aggregatePublicKey, [h, sig], MPCP_output, petitionOwnerStr);
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

  // // now finally check if the cred wasn't already spent
  // const wasCredAlreadySpent = await checkUsedId(id);
  // if (DEBUG) {
  //   console.log(`Was cred already spent: ${wasCredAlreadySpent}`);
  // }
  //
  // if (isProofValid && !wasCredAlreadySpent && isSignatureValid) {
  //   await insertUsedId(id);
  //   // await changeBalance(publicKeys[petitionOwner], credAttributes.value);
  // }


  // EDIT: send to issuer to insert used zeta

  const t1 = new Date().getTime();
  console.log('Deposit took: ', t1 - t0);

  res.status(200)
    .json({
      success: true,
    });
});

export default router;
