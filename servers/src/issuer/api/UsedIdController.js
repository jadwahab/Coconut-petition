import express from 'express';
import bodyParser from 'body-parser';
import { checkUsedId } from '../utils/DatabaseManager';
import { ctx } from '../../globalConfig';
import { DEBUG } from '../config/appConfig';

const router = express.Router();

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());


router.post('/', async (req, res) => {
  if (DEBUG) {
    console.log('Used id post');
  }
  const id_bytes = req.body.id;
  const id = ctx.BIG.fromBytes(id_bytes);
  const wasIdUsed = await checkUsedId(id);

  res.status(200)
    .json({
      wasIdUsed: wasIdUsed,
    });
});

export default router;
