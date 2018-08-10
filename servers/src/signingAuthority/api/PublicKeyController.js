import express from 'express';
import bodyParser from 'body-parser';
import { pkBytes, pkElGamalBytes } from '../config/CredSigSetup';
import { DEBUG } from '../config/appConfig';

const router = express.Router();

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());


router.get('/', (req, res) => {
  if (DEBUG) {
    console.log('>pk get');
  }
  res.status(200).json({
    pk: pkBytes,
    pkElGamal: pkElGamalBytes,
  });
});

export default router;
