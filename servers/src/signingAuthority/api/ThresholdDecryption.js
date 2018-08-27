import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'isomorphic-fetch';
import { ctx, params, signingServers, petitionOwner } from '../../globalConfig';
import { ElGamalkeys } from '../config/CredSigSetup';
import { DEBUG } from '../config/appConfig';
import { fromBytesVotes, getBytesVotes } from '../../BytesConversion';
import ElGamal from '../../ElGamal';

const router = express.Router();

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

const sendThresholdDecryption = async (server, petitionID, enc_votes, decIndex) => {
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
        petitionID: petitionID,
      }),
    });
    if (response.status === 200) {
      console.log(`Successfully sent threshold decryption to ${server}`);
      return true;
    }
    console.log(`Threshold decryption send to ${server} failed`);
    return false;

  } catch (err) {
    console.warn(err);
    console.warn(`Call to ${server} was unsuccessful`);
  }
};

const sendResult = async (server, petitionID, result) => {
  try {
    const response = await
    fetch(`http://${server}/result`, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        petitionID: petitionID,
        result: result,
      }),
    });
    if (response.status === 200) {
      console.log(`Successfully sent result to ${server}`);
      return true;
    }
    console.log(`Result send to ${server} failed`);
    return false;

  } catch (err) {
    console.warn(err);
    console.warn(`Call to ${server} was unsuccessful`);
  }
};

router.post('/', async (req, res) => {
  const t0 = new Date().getTime();
  if (DEBUG) {
    console.log('>threshold decryption');
  }

  let responseStatus = -1;

  try {
    const [G, o, g1, g2, e, h1] = params;
    const enc_votes = fromBytesVotes(req.body.votes_bytes);
    const [enc_v, enc_v_not] = enc_votes;
    const [a_enc_v, b_enc_v] = enc_v;
    const [a_enc_v_not, b_enc_v_not] = enc_v_not;
    a_enc_v.affine();
    b_enc_v.affine();
    a_enc_v_not.affine();
    b_enc_v_not.affine();

    const hdec = ElGamal.decrypt(params, ElGamalkeys[0], [a_enc_v, b_enc_v]);
    const hdec_not = ElGamal.decrypt(params, ElGamalkeys[0], [a_enc_v_not, b_enc_v_not]);
    
    const decIndex = req.body.decIndex;
    const petitionID = req.body.petitionID;

    if (decIndex === 0) {
      const dec = ElGamal.logh(params, hdec, h1, 100);
      const dec_not = ElGamal.logh(params, hdec_not, h1, 100);

      const yes_string = dec.toString();
      const no_string = dec_not.toString();
      console.log(`Petition ${petitionID}:`);
      console.log(`Number of "yes" votes: ${parseInt(yes_string, 16)}`);
      console.log(`Number of "no" votes: ${parseInt(no_string, 16)}`);
      
      // send result to petitionOwner
      const result = {
        yes: yes_string,
        no: no_string,
      };
      const sentResult = sendResult(petitionOwner, petitionID, result);
      if (!sentResult) {
        console.log('Error in sending the threshold decryption');
      }
    } else {
      const encV = [a_enc_v, hdec];
      const encVNot = [a_enc_v_not, hdec_not];
      const enc_votes_new = [encV, encVNot];

      const sentThreshdec = await sendThresholdDecryption(signingServers[decIndex - 1], 
        petitionID, enc_votes_new, (decIndex - 1) );
      if (!sentThreshdec) {
        console.log('Error in sending the threshold decryption');
      }
    }

    responseStatus = 200;
  } catch (err) {
    console.warn(err);
    responseStatus = 400;
  }

  const t1 = new Date().getTime();
  console.log('Request took: ', t1 - t0);
  res.sendStatus(responseStatus);
});

export default router;
