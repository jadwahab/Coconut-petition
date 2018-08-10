import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'isomorphic-fetch';
import { ctx, params, signingServers } from '../../globalConfig';
import { DEBUG } from '../config/appConfig';
import { fromBytesVotes, getBytesVotes } from '../../BytesConversion';
import ElGamal from '../../ElGamal';
import { storage } from './CredVoteController';

const results = [];

const router = express.Router();

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());


router.post('/', async (req, res) => {
  if (DEBUG) {
    console.log('>post results');
  }
  let responseStatus = -1;

  try {
    const petitionID = req.body.petitionID;
    const result = req.body.result;

    if (DEBUG) {
      console.log(`Petition ${petitionID}:`);
      console.log(`Number of "yes" votes: ${parseInt(result.yes, 16)}`);
      console.log(`Number of "no" votes: ${parseInt(result.no, 16)}`);
    }
    const petitionResult = {
      petitionID: petitionID,
      result: result,
    };
    results.push(petitionResult);

    responseStatus = 200;
  } catch (err) {
    console.warn(err);
    responseStatus = 400;
  }
  res.sendStatus(responseStatus);
});

router.get('/:id', (req, res) => {
  console.log('>get results');
  const petitionResult = results.find(result => result.petitionID === req.params.id);
  if (petitionResult) {
    if (DEBUG) {
      const client_address = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
      console.log(`Sent results of petition ${petitionResult.petitionID} to ${client_address}`);
    }
    res.status(200).json({ petitionResult: petitionResult });
  } else {
    if (DEBUG) {
      console.log(`Results not ready yet for ${req.params.id}`);
    }
    res.sendStatus(400);
  }
});

export default router;
