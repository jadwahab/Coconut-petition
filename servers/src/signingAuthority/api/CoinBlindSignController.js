import express from 'express';
import bodyParser from 'body-parser';
import CoinSig from '../../CoinSig';
import { params, sk } from '../config/CoinSigSetup';
import { DEBUG } from '../config/appConfig';
import ElGamal from '../../ElGamal';
import { verifySignRequest } from '../../SigningCredential';
import { sessionSignatures, publicKeys } from '../cache';
import { issuer, ctx } from '../../globalConfig';
import { getPublicKey, hashToPointOnCurve, fromBytesProof_Auth, verifyProofOfSecret_Auth } from '../../auxiliary';

const router = express.Router();

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

router.post('/', async (req, res) => {
  const t0 = new Date().getTime();
  if (DEBUG) {
    console.log('blindsign post');
  }
  let responseStatus = -1;
  let signatureBytes = null;
  try {
    const signingCoin = req.body.coin;
    const ElGamalPKBytes = req.body.ElGamalPKBytes;

    // firstly check if the server has not already signed this coin
    if (sessionSignatures.has(signingCoin.issuedCoinSig)) {
      throw new Error('This coin was already signed before!');
    } else {
      sessionSignatures.add(signingCoin.issuedCoinSig);
    }

    if (publicKeys[issuer] == null || publicKeys[issuer].length <= 0) {
      const publicKey = await getPublicKey(issuer);
      publicKeys[issuer] = publicKey;
    }

    const isRequestLegit = verifySignRequest(signingCoin, publicKeys[issuer]);
    if (!isRequestLegit) {
      throw new Error('Coin was tampered with.');
    }

    const reducer = (acc, cur) => acc + cur;

    const coinStr =
      signingCoin.pk_client_bytes.reduce(reducer) + // client's key
      signingCoin.pk_coin_bytes.reduce(reducer) + // coin's pk
      signingCoin.issuedCoinSig[0].reduce(reducer) + // issuer sig
      signingCoin.issuedCoinSig[1].reduce(reducer); // client sig

    const h_comit = hashToPointOnCurve(coinStr);

    const ElGamalPK = ElGamal.getPKFromBytes(params, ElGamalPKBytes);
    const proof = fromBytesProof_Auth(signingCoin.proof);
    const coin_pk = ctx.ECP.fromBytes(signingCoin.pk_coin_bytes);
    const [enc_sk_a_bytes, enc_sk_b_bytes] = signingCoin.enc_sk_bytes;
    const enc_sk_a = ctx.ECP.fromBytes(enc_sk_a_bytes);
    const enc_sk_b = ctx.ECP.fromBytes(enc_sk_b_bytes);
    const enc_sk = [enc_sk_a, enc_sk_b];
    const isProofValid = verifyProofOfSecret_Auth(params, h_comit, coin_pk, ElGamalPK, enc_sk, proof);

    if (!isProofValid) {
      console.log('Proof was not correct');
      throw new Error('Proof was not correct');
    }

    if (DEBUG) {
      console.log(`Was credntial proof valid: ${isProofValid}`);
    }

    const [h, enc_sig] = CoinSig.mixedSignCoin(params, sk, signingCoin);
    const hBytes = [];
    const enc_sig_a_Bytes = [];
    const enc_sig_b_Bytes = [];

    h.toBytes(hBytes);
    enc_sig[0].toBytes(enc_sig_a_Bytes);
    enc_sig[1].toBytes(enc_sig_b_Bytes);


    if (DEBUG) {
      console.log(`Signed the coin. \n h: ${h.toString()}, \n enc_sig_a: ${enc_sig[0].toString()} \n enc_sig_b: ${enc_sig[1].toString()}`);
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

router.get('/', (req, res) => {
  console.log('blindsign get');
  res.status(200).json({ hi: 'hi' });
});

export default router;
