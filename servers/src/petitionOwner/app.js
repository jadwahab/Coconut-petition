import express from 'express';
import CredVoteController from './api/CredVoteController';
import ServerStatusController from './api/ServerStatusController';
import PublicKeyController from './api/PublicKeyController';
import VoteResultController from './api/VoteResultController';

const app = express();

// to enable cors
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

app.use('/pk', PublicKeyController);
app.use('/vote', CredVoteController);
app.use('/result', VoteResultController);
app.use('/status', ServerStatusController);


export default app;
