import 'babel-polyfill';
import app from './app';
import { setupKeys } from './config/KeySetup';

if (process.argv.length < 3) {
  throw new Error('No port number provided');
}

const port = parseInt(process.argv[2], 10);

const server = app.listen(port, () => {
  setupKeys();
  console.log(`Server Started on port ${port}`);
});
