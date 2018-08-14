import express from 'express';
import PublicKeyController from './api/PublicKeyController';
import ServerStatusController from './api/ServerStatusController';
import CredIssuanceController from './api/CredIssuanceController';
import UsedIdController from './api/UsedIdController';
import DepositCredController from './api/DepositCredController';

const app = express();

// to enable cors
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

app.use('/pk', PublicKeyController);
app.use('/status', ServerStatusController);
app.use('/getcred', CredIssuanceController);
app.use('/checkid', UsedIdController);
app.use('/depositcred', DepositCredController);

export default app;
