import 'babel-polyfill';
import app from './app';
import { setupCoinSigKeys } from './config/CoinSigSetup';

if (process.argv.length < 3) {
  throw new Error('No port number provided');
}

const port = parseInt(process.argv[2], 10);

const server = app.listen(port, () => {
  setupCoinSigKeys();
  console.log(`Server Started on port ${port}`);
});
