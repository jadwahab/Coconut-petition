import express from 'express';
import bodyParser from 'body-parser';
import CredSig from '../../CredSig';
import { params, sk } from '../config/CredSigSetup';
import { DEBUG } from '../config/appConfig';
import ElGamal from '../../ElGamal';
import { verifySignRequest } from '../../SigningCred';
import { sessionSignatures, publicKeys } from '../cache';
import { issuer, ctx } from '../../globalConfig';
import { getPublicKey } from '../../auxiliary';
import { fromBytesProof_Auth } from '../../BytesConversion';
import { hashToPointOnCurve, verifyProofOfSecret_Auth } from '../../Proofs';

const router = express.Router();

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

router.post('/', async (req, res) => {
  const t0 = new Date().getTime();
  if (DEBUG) {
    console.log('>blindsign post');
  }
  let responseStatus = -1;
  let signatureBytes = null;
  try {
    const signingCred = req.body.cred;
    const ElGamalPKBytes = req.body.ElGamalPKBytes;

    // first check if the server has not already signed this cred
    if (sessionSignatures.has(signingCred.requestSig)) {
      throw new Error('This cred was already signed before!');
    } else {
      sessionSignatures.add(signingCred.requestSig);
    }

    if (publicKeys[issuer] == null || publicKeys[issuer].length <= 0) {
      const publicKey = await getPublicKey(issuer);
      publicKeys[issuer] = publicKey;
    }

    // check if issuer signature valid
    // const isRequestLegit = verifySignRequest(signingCred, publicKeys[issuer]);
    // if (!isRequestLegit) {
    //   throw new Error('Cred was tampered with.');
    // }

    //
    // const requestSig = req.body.requestSig;

    // const reducer = (acc, cur) => acc + cur;
    // const requestStr =
    //   signingCred.pk_client_bytes.reduce(reducer) + // client's key
    //   signingCred.pk_cred_bytes.reduce(reducer); // cred's pk

    // const sha = ctx.ECDH.HASH_TYPE;
    // const [C, D] = requestSig;

    // const isSignValid = ctx.ECDH.ECPVP_DSA(sha, signingCred.pk_client_bytes, requestStr, C, D) === 0;
    // if (!isSignValid) {
    //   console.log('Signature was not valid');
    //   throw new Error('Signature was not valid');
    // }
    //


    const reducer = (acc, cur) => acc + cur;

    const credStr =
      signingCred.pk_client_bytes.reduce(reducer) + // client's key
      signingCred.pk_cred_bytes.reduce(reducer); // cred's pk


    //
    const requestStr = credStr +
    signingCred.enc_sk_bytes[0].reduce(reducer) +
    signingCred.enc_sk_bytes[1].reduce(reducer);

    const sha = ctx.ECDH.HASH_TYPE;
    const [C, D] = signingCred.requestSig;
    const isSignValid = ctx.ECDH.ECPVP_DSA(sha, signingCred.pk_client_bytes, requestStr, C, D) === 0;
    if (!isSignValid) {
      console.log('Signature was not valid');
      throw new Error('Signature was not valid');
    }
    //


    const h_commit = hashToPointOnCurve(credStr);

    const ElGamalPK = ElGamal.getPKFromBytes(params, ElGamalPKBytes);
    const proof = fromBytesProof_Auth(signingCred.proof);
    const cred_pk = ctx.ECP.fromBytes(signingCred.pk_cred_bytes);
    const [enc_sk_a_bytes, enc_sk_b_bytes] = signingCred.enc_sk_bytes;
    const enc_sk_a = ctx.ECP.fromBytes(enc_sk_a_bytes);
    const enc_sk_b = ctx.ECP.fromBytes(enc_sk_b_bytes);
    const enc_sk = [enc_sk_a, enc_sk_b];
    const isProofValid = verifyProofOfSecret_Auth(params, h_commit, cred_pk, ElGamalPK, enc_sk, proof);

    if (!isProofValid) {
      console.log('Proof was not correct');
      throw new Error('Proof was not correct');
    }

    if (DEBUG) {
      console.log(`Was credntial proof valid: ${isProofValid}`);
    }

    const [h, enc_sig] = CredSig.mixedSignCred(params, sk, signingCred);
    const hBytes = [];
    const enc_sig_a_Bytes = [];
    const enc_sig_b_Bytes = [];

    h.toBytes(hBytes);
    enc_sig[0].toBytes(enc_sig_a_Bytes);
    enc_sig[1].toBytes(enc_sig_b_Bytes);


    if (DEBUG) {
      console.log(`Signed the cred. \n h: ${h.toString()}, \n enc_sig_a: ${enc_sig[0].toString()} \n enc_sig_b: ${enc_sig[1].toString()}`);
    }

    signatureBytes = [hBytes, [enc_sig_a_Bytes, enc_sig_b_Bytes]];

    responseStatus = 200;
  } catch (err) {
    console.log(err);
    responseStatus = 400;
  }
  const t1 = new Date().getTime();
  console.log('Request took: ', t1 - t0);
  res.status(responseStatus).json({ signature: signatureBytes });
});

// EDIT : wtf is this
router.get('/', (req, res) => {
  console.log('blindsign get');
  res.status(200).json({ hi: 'hi' });
});

export default router;
