import express from 'express';
import PublicKeyController from './api/PublicKeyController';
import CredBlindSignController from './api/CredBlindSignController';

const app = express();

// to enable cors
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

app.use('/blindsign', CredBlindSignController);
app.use('/pk', PublicKeyController);

export default app;
