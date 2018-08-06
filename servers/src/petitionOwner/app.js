import express from 'express';
import CredSpendController from './api/CredSpendController';
import ServerStatusController from './api/ServerStatusController';
import PublicKeyController from './api/PublicKeyController';

const app = express();

// to enable cors
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

app.use('/pk', PublicKeyController);
app.use('/spend', CredSpendController);
app.use('/status', ServerStatusController);


export default app;
