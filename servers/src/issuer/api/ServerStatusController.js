import express from 'express';
import bodyParser from 'body-parser';

const router = express.Router();

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());


router.get('/', (req, res) => {
  res.status(200).json({
    alive: true,
  });
});

export default router;
